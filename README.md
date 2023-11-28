# esp-netatmo-security-api

Simple API to access Netatmo HOME + Security data for esp idf. For more detailed information see http://dev.netatmo.com

I have no relation with the netatmo company.

## Install

```sh
    mkdir components
    cd components
    git submodule add <gitrepo>
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
	components/esp-netatmo-security-api/src/gdig2.crt.pem
```

## Information
The file `src/gdig2.crt.pem` has been download from this [repository](https://certs.godaddy.com/repository/).
The x509_crt_bundle do not work with netatmo website.

