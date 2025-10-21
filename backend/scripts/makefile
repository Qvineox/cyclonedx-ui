PROTO_DIR=api/proto
GO_OUT=gen/go
TS_OUT=gen/ts

PROTOC_INC=C:\Users\ydlysak\protoc-32.0\include
PROTO_GRPC_GW_INC=C:\Users\YDLysak\go\pkg\mod\github.com\grpc-ecosystem\grpc-gateway@v1.16.0\third_party\googleapis

# C:\Users\YDLysak\protoc\include
# C:\Users\YDLysak\go\pkg\mod\github.com\grpc-ecosystem\grpc-gateway@v1.16.0\third_party\googleapis

all: go gateway

go:
	protoc -I . -I $(PROTO_DIR) -I $(PROTOC_INC) -I $(PROTO_GRPC_GW_INC) \
		--go_out=$(GO_OUT) --go_opt=paths=source_relative \
		--go-grpc_out=$(GO_OUT) --go-grpc_opt=paths=source_relative,require_unimplemented_servers=false \
		api/proto/sbom/v1/*.proto

# https://grpc-ecosystem.github.io/grpc-gateway/docs/mapping/customizing_openapi_output/

gateway:
	protoc -I . -I $(PROTO_DIR) -I $(PROTOC_INC) -I $(PROTO_GRPC_GW_INC) \
		--grpc-gateway_out=$(GO_OUT) --grpc-gateway_opt=paths=source_relative \
		--openapiv2_out=$(GO_OUT) --openapiv2_opt=allow_merge=true \
		api/proto/sbom/v1/*.proto

ts:
	protoc -I . -I $(PROTO_DIR) -I $(PROTOC_INC) -I $(PROTO_GRPC_GW_INC) \
		--ts_proto_out=$(TS_OUT) \
		--ts_proto_opt=esModuleInterop=true,forceLong=string,outputServices=grpc-js \
		api/proto/sbom/v1/*.proto

clean:
	del /S /Q $(GO_OUT)\* || echo ""
	del /S /Q $(TS_OUT)\* || echo ""

.PHONY: all go gateway ts clean
