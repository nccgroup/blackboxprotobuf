protoc:
	python3 -m grpc_tools.protoc -I./ --python_out=./ --grpc_python_out=./ Test.proto
certs:
	openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
