idf_component_register(
    SRC_DIRS src
    INCLUDE_DIRS src
    REQUIRES nvs_flash json esp_http_client
    EMBED_TXTFILES src/gdig2.crt.pem
)