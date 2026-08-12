module jwt

import x.json2
import encoding.base64

pub type JsonAny = json2.Any

pub fn base64_url_encode(data string) string {
	return base64.url_encode_str(data).replace('=', '')
}

pub fn base64_url_decode(data string) string {
	return base64.url_decode_str(data)
}

pub fn json_encode[T](val T) string {
	return json2.encode[T](val)
}

pub fn json_decode[T](s string) !T {
	return json2.decode[T](s)!
}