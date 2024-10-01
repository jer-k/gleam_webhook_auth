import envoy
import gleam/bit_array
import gleam/bytes_builder
import gleam/crypto
import gleam/erlang/process
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/io
import gleam/result
import gleam/string
import logging
import mist.{type Connection, type ResponseData}

pub fn main() {
  logging.configure()

  let assert Ok(_) =
    handle_request
    |> mist.new
    |> mist.port(3001)
    |> mist.start_http

  process.sleep_forever()
}

fn handle_request(req: Request(Connection)) -> Response(ResponseData) {
  case request.path_segments(req) {
    ["events"] -> events(req)
    _ -> not_found()
  }
}

fn events(req: Request(Connection)) -> Response(ResponseData) {
  case req.method {
    http.Post -> create_event(req)
    _ -> not_found()
  }
}

fn create_event(req: Request(Connection)) {
  case is_valid_request(request_body(req), signature_digest(req)) {
    True ->
      response.new(200)
      |> response.set_body(mist.Bytes(bytes_builder.from_string("Ok")))
    False ->
      response.new(401)
      |> response.set_body(
        mist.Bytes(bytes_builder.from_string("Could not authenticate")),
      )
  }
}

fn signature_digest(req: Request(Connection)) {
  case request.get_header(req, "x-hub-signature-256") {
    Ok(header) -> {
      Ok(bit_array.from_string(header))
    }
    Error(message) -> Error(message)
  }
}

fn secret() {
  case envoy.get("WEBHOOK_SECRET") {
    Ok(secret) -> bit_array.from_string(secret)
    Error(_) -> {
      io.debug("DIDNT GET ENVVAR")
      bit_array.from_string("ERROR")
    }
  }
}

fn request_body(req: Request(Connection)) {
  let body =
    mist.read_body(req, 1024 * 1024 * 10)
    |> result.map(fn(req) { req.body })

  case body {
    Ok(body) -> body
    // If we can't get the body, an empty string should fail to match
    // the signature in the header
    Error(_) -> bit_array.from_string("")
  }
}

fn expected_signature(request_body: BitArray) -> BitArray {
  let hmac =
    crypto.hmac(request_body, crypto.Sha256, secret())
    |> bit_array.base16_encode
    |> string.lowercase

  string.append("sha256=", hmac) |> bit_array.from_string
}

fn is_valid_request(request_body: BitArray, digest: Result(BitArray, Nil)) {
  case digest {
    Ok(digest) -> {
      let signature = expected_signature(request_body)
      crypto.secure_compare(signature, digest)
    }
    Error(_) -> False
  }
}

fn not_found() -> Response(ResponseData) {
  response.new(404)
  |> response.set_body(mist.Bytes(bytes_builder.from_string("Not Found")))
}
