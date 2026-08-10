module jwt

enum JobTitle {
	manager
	executive
	worker
}

struct Employee {
mut:
	name   string
	family string @[json: '-'] // this field will be skipped
	age    int
	salary f32
	title  JobTitle @[json: 'ETitle'] // the key for this field will be 'ETitle', not 'title'
	// the JSON property is omitted while the field keeps its zero/default value
	notes string @[omitempty]
}

fn test_json() {
	x := Employee{'Peter', 'Begins', 28, 95000.5, .worker, ''}
	s := json_encode[Employee](x)
	assert s == '{"name":"Peter","age":28,"salary":95000.5,"ETitle":"worker"}'

	res := '{"name":"Peter","age":28,"salary":95000.5,"ETitle":"worker"}'
	deres := json_decode[Employee](res)!
	assert "Peter" == deres.name
	assert 28 == deres.age
	assert 95000.5 == deres.salary
	assert .worker == deres.title
}

fn test_base64() {
	test := base64_url_decode('SGVsbG8gQmFzZTY0VXJsIGVuY29kaW5nIQ')
	assert test == 'Hello Base64Url encoding!'

	test2 := base64_url_encode('Hello Base64Url encoding!')
	assert test2 == 'SGVsbG8gQmFzZTY0VXJsIGVuY29kaW5nIQ'
}
