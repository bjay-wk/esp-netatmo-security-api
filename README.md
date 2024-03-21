# esp-netatmo-security-api

Simple API to access Netatmo HOME + Security data for esp idf. For more detailed information see http://dev.netatmo.com

I have no relation with the netatmo company.

## Install

In the file `src/idf_component.yml` add:
```sh
    esp-netatmo-security-api:
        git: https://github.com/bjay-wk/esp-netatmo-security-api.git
```

then in idf_component_register in the file CMakeLists.txt you will add

```
idf_component_register(
    ...
    REQUIRES netatmo
)
```

if you are using platform io you should add this to platform.ini
```ini
[env]
board_build.embed_txtfiles =
	managed_components/esp-netatmo-security-api/src/gdig2.crt.pem
```

## Information
The file `src/gdig2.crt.pem` has been download from this [repository](https://certs.godaddy.com/repository/).
The x509_crt_bundle do not work with netatmo website.

