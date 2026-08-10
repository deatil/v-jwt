module jwt

fn test_validator() {
	check1 := "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3ODQyMzg4fQ.dGVzdC1zaWduYXR1cmU"
	now := i64(1767812388)

	mut token := Token.new()
	token.parse(check1)

	validator := Validator.new(token)

	mut status := false

	status = validator.has_been_issued_by(["iss"])
	assert true == status

	status = validator.is_related_to(["sub"])
	assert true == status

	status = validator.is_identified_by("jti rrr")
	assert true == status

	status = validator.is_permitted_for(["example.com"])
	assert true == status

	status = validator.has_been_issued_before(now)
	assert true == status

	status = validator.is_expired(now)
	assert false == status

	// ==========

	status = validator.has_been_issued_before(1567842389)
	assert true == status

	status = validator.is_minimum_time_before(1567842389)
	assert true == status

	status = validator.is_expired(1767842389)
	assert true == status

}

fn test_validator2() {
	check1 := "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3ODQyMzg4fQ.dGVzdC1zaWduYXR1cmU"

	mut token := Token.new()
	token.parse(check1)

	mut validator2 := Validator.new(token)
	validator2.with_leeway(3)

	mut status := false

	status = validator2.has_been_issued_before(1567842391)
	assert true == status

	status = validator2.has_been_issued_before(1567842384)
	assert false == status

	status = validator2.is_minimum_time_before(1567842391)
	assert true == status

	status = validator2.is_minimum_time_before(1567842384)
	assert false == status

	status = validator2.is_expired(1767842392)
	assert true == status

	status = validator2.is_expired(1767842389)
	assert false == status

}