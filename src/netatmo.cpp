#include "netatmo.hpp"

#include <algorithm>
#include <esp_http_client.h>
#include <esp_log.h>
#include <esp_random.h>
#include <nvs.h>

#define TAG "NETATMO"
#define WEB_URL "https://api.netatmo.com"

#define MAX_HTTP_OUTPUT_BUFFER 2 * 1024
#define MAX_HTTP_OUTPUT_BUFFER_CALLOC 26 * 1024
#define CLIENT_ID CONFIG_NETATMO_API_KEY
#define CLIENT_SECRET CONFIG_NETATMO_SECRET_API
#define NVS_NAMESPACE "NETATMO"
#define NVS_REFRESH_TOKEN "refresh"
#define NVS_ACCESS_TOKEN "access"

extern const char gdig2_crt_pem_start[] asm("_binary_gdig2_crt_pem_start");

char Netatmo::unique_state[10] = "";

static std::string scope_name(Netatmo::Scopes scopes, const char *separator);
static std::string gateway_type_name(Netatmo::GatewayTypes gateway_type,
                                     const char *separator);
void gen_random(char *string, const int size);
char *get_token(const char *key);

int Netatmo::homes_data(const char *home_id,
                        Netatmo::GatewayTypes gateaway_types, cJSON **output) {
  bool has_param = false;
  std::string path = "/api/homesdata";
  if (home_id) {
    path += "?home_id=";
    path += home_id;
    has_param = true;
  }
  if (gateaway_types != Netatmo::GatewayTypes::None) {
    path += (has_param ? "&" : "?");
    path +=
        "gateway_types=" + gateway_type_name(gateaway_types, "gateway_types=");
  }
  return https_with_hostname_path(path.c_str(), HTTP_METHOD_GET, NULL, output);
}

int Netatmo::home_status(const char *home_id,
                         Netatmo::GatewayTypes gateaway_types, cJSON **output) {
  std::string path = std::string("/api/homestatus?home_id=") + home_id;
  if (gateaway_types != Netatmo::GatewayTypes::None) {
    path +=
        "?gateway_types=" + gateway_type_name(gateaway_types, "gateway_types=");
  }
  ESP_LOGI(TAG, "%s", path.c_str());
  return https_with_hostname_path(path.c_str(), HTTP_METHOD_GET, NULL, output);
}

int Netatmo::get_events(const std::string &home_id,
                        Netatmo::GatewayTypes gateaway_types,
                        const std::string &event_id,
                        const std::string &person_id,
                        const std::string &device_id,
                        const std::string &module_id, int offset, int size,
                        const std::string &locale, cJSON **output) {
  std::string url = "/api/getevents?home_id=" + home_id;
  if (Netatmo::GatewayTypes::None != gateaway_types) {
    url +=
        "?gateway_types=" + gateway_type_name(gateaway_types, "gateway_types=");
  }
  if (!event_id.empty())
    url += "&event_id=" + event_id;
  if (!person_id.empty())
    url += "&person_id=" + person_id;
  if (!device_id.empty())
    url += "&device_id=" + device_id;
  if (!module_id.empty())
    url += "&module_id" + module_id;
  if (offset >= 0)
    url += "&offset=" + std::to_string(offset);
  if (size > 0)
    url += "&size=" + std::to_string(size);
  if (!locale.empty())
    url += "&locale=" + locale;
  return https_with_hostname_path(url.c_str(), HTTP_METHOD_GET, NULL, output);
}

int Netatmo::set_persons_away(std::string home_id, std::string persone_id) {
  std::string url = "/api/setpersonsaway?home_id=" + home_id;
  if (!persone_id.empty())
    url += "&person_id=" + persone_id;
  return https_with_hostname_path(url.c_str(), HTTP_METHOD_POST, NULL, NULL);
}

int Netatmo::set_persons_home(std::string home_id,
                              std::vector<std::string> &person_ids) {
  std::string url = "/api/setpersonshome?home_id=" + home_id;
  for (int i = 0; i < person_ids.size(); ++i) {
    if (!person_ids[i].empty())
      url += "&person_ids[]=" + person_ids[i];
  }
  return https_with_hostname_path(url.c_str(), HTTP_METHOD_POST, NULL, NULL);
}

int Netatmo::set_state(const cJSON *state) {
  return https_with_hostname_path("/api/setstate", HTTP_METHOD_POST, state,
                                  NULL);
}

int Netatmo::add_webhook(std::string webhookurl) {
  std::string url = "/api/addwebhook?url=" + webhookurl;
  return https_with_hostname_path(url.c_str(), HTTP_METHOD_POST, NULL, NULL);
}

int Netatmo::drop_webhook() {
  return https_with_hostname_path("/api/dropwebhook", HTTP_METHOD_POST, NULL,
                                  NULL);
}

char *Netatmo::get_redirect_url(const char *redirectURI,
                                Netatmo::Scopes scopes) {
  gen_random(Netatmo::unique_state, sizeof(Netatmo::unique_state));
  auto string = std::string(WEB_URL "/oauth2/authorize"
                                    "?client_id=" CLIENT_ID "&redirect_uri=") +
                redirectURI + "&scope=" + scope_name(scopes, "%20") +
                "&state=" + Netatmo::unique_state;
  return strdup(string.c_str());
}

bool Netatmo::check_state(const char *state) {
  return strcmp(Netatmo::unique_state, state) == 0;
}

int Netatmo::inner_request_tokens(const char *path, const std::string &data) {
  esp_http_client_config_t config = {};
  char output_buffer[MAX_HTTP_OUTPUT_BUFFER] = {0};
  const std::string url = std::string(WEB_URL) + path;
  config.url = url.c_str();
  config.transport_type = HTTP_TRANSPORT_OVER_SSL;
  config.cert_pem = gdig2_crt_pem_start;
  esp_http_client_handle_t client = esp_http_client_init(&config);
  esp_http_client_set_method(client, HTTP_METHOD_POST);
  esp_http_client_set_header(client, "Content-Type",
                             "application/x-www-form-urlencoded;charset=UTF-8");
  esp_err_t err = esp_http_client_open(client, data.length());
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
  } else if (esp_http_client_write(client, data.c_str(), data.length()) < 0) {
    ESP_LOGE(TAG, "Write failed");
  } else if (esp_http_client_fetch_headers(client) < 0) {
    ESP_LOGE(TAG, "HTTP client fetch headers failed");
  } else if (esp_http_client_read_response(client, output_buffer,
                                           MAX_HTTP_OUTPUT_BUFFER) < 0) {
    ESP_LOGE(TAG, "Failed to read response");
  }

  esp_http_client_close(client);
  cJSON *output = cJSON_Parse(output_buffer);
  const int status_code = esp_http_client_get_status_code(client);
  if (status_code == 200) {
    const cJSON *c_refresh_token =
        cJSON_GetObjectItemCaseSensitive(output, "refresh_token");
    const cJSON *c_access_token =
        cJSON_GetObjectItemCaseSensitive(output, "access_token");
    if (cJSON_IsString(c_access_token) && c_access_token->valuestring != NULL &&
        cJSON_IsString(c_refresh_token) &&
        c_refresh_token->valuestring != NULL) {
      save_token(c_access_token->valuestring, c_refresh_token->valuestring);
    }
    cJSON_Delete(output);
  }
  esp_http_client_cleanup(client);
  return status_code;
}

int Netatmo::request_token(const std::string code, const char *redirectURI,
                           Scopes scopes) {
  ESP_LOGI(TAG, "Request access token");
  const std::string data =
      std::string("grant_type=authorization_code"
                  "&client_id=" CLIENT_ID "&client_secret=" CLIENT_SECRET
                  "&scope=") +
      scope_name(scopes, " ") + "&redirect_uri=" + redirectURI +
      "&code=" + code;
  return inner_request_tokens("/oauth2/token", data);
}

int Netatmo::refresh_token() {
  ESP_LOGI(TAG, "Request refresh token");
  auto s_refresh_token = getrefresh_token();
  std::string data =
      std::string("grant_type=refresh_token"
                  "&client_id=" CLIENT_ID "&client_secret=" CLIENT_SECRET
                  "&refresh_token=") +
      s_refresh_token;
  return inner_request_tokens("/oauth2/token", data);
}

void Netatmo::save_token(const char *access_token, const char *refresh_token) {
  nvs_handle_t handle_1;
  ESP_LOGI(TAG, "Saving access token and refresh_token");
  auto err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle_1);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Error (%s) opening NVS handle!\n", esp_err_to_name(err));
  }
  err = nvs_set_str(handle_1, NVS_ACCESS_TOKEN, access_token);
  if (ESP_OK != err) {
    ESP_LOGE(TAG, "access str: %s", esp_err_to_name(err));
  }
  err = nvs_set_str(handle_1, NVS_REFRESH_TOKEN, refresh_token);
  if (ESP_OK != err) {
    ESP_LOGE(TAG, "refresh str: %s", esp_err_to_name(err));
  }
  err = nvs_commit(handle_1);
  if (ESP_OK != err) {
    ESP_LOGE(TAG, "commit: %s", esp_err_to_name(err));
  }
  nvs_close(handle_1);
}

char *Netatmo::getaccess_token() { return get_token(NVS_ACCESS_TOKEN); }

char *Netatmo::getrefresh_token() { return get_token(NVS_REFRESH_TOKEN); }

inline char *get_token(const char *key) {
  nvs_handle_t handle_1;
  size_t required_size = 0;
  nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle_1);
  nvs_get_str(handle_1, key, NULL, &required_size);
  char *buf = (char *)malloc(required_size);
  auto err = nvs_get_str(handle_1, key, buf, &required_size);
  if (ESP_OK != err) {
    ESP_LOGE(TAG, "%s: %s", key, esp_err_to_name(err));
    free(buf);
    buf = NULL;
  }
  nvs_close(handle_1);
  return buf;
}

int Netatmo::https_with_hostname_path(const char *path,
                                      esp_http_client_method_t method,
                                      const cJSON *input_data,
                                      [[maybe_unused]] cJSON **output) {
  bool retry_access_token = false;
  esp_http_client_config_t config = {};
  char *output_buffer = NULL;
  const std::string url = std::string(WEB_URL) + path;
  config.url = url.c_str();
  config.transport_type = HTTP_TRANSPORT_OVER_SSL;
  config.cert_pem = gdig2_crt_pem_start;
  esp_http_client_handle_t client = esp_http_client_init(&config);
  esp_http_client_set_method(client, method);
  char *auth_str = getaccess_token();
  const std::string auth = std::string("Bearer ") + auth_str;
  esp_http_client_set_header(client, "accept", "application/json");
  esp_http_client_set_header(client, "Authorization", auth.c_str());
  if (method == HTTP_METHOD_POST) {
    esp_http_client_set_header(client, "Content-Type", "application/json");
  }
  int data_len = 0;
  char *data = NULL;
  if (input_data) {
    data = cJSON_PrintUnformatted(input_data);
    data_len = strlen(data);
  }
  esp_err_t err = esp_http_client_open(client, data_len);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
  } else if (data != NULL &&
             esp_http_client_write(client, data, data_len) < 0) {
    ESP_LOGE(TAG, "Write failed");
  } else if (esp_http_client_fetch_headers(client) < 0) {
    ESP_LOGE(TAG, "HTTP client fetch headers failed");
  } else {
    output_buffer = (char *)calloc(MAX_HTTP_OUTPUT_BUFFER_CALLOC, 1);
    int total_read = 0;
    int read = 0;
    do {
      read = esp_http_client_read_response(client, output_buffer + total_read,
                                           MAX_HTTP_OUTPUT_BUFFER_CALLOC -
                                               total_read);
      total_read += read;
    } while (read > 0);
    // ESP_LOGI(TAG, "%s", output_buffer);
    static const char error_str[] = "{\"error\":{\"code\":3,";
    if (strncmp(error_str, output_buffer, sizeof(error_str) - 1) == 0) {
      ESP_LOGI(TAG, "%s", output_buffer);
      retry_access_token = true;
    } else if (output) {
      *output = cJSON_Parse(output_buffer);
    }
    free(output_buffer);
  }

  esp_http_client_close(client);
  if (input_data)
    free(data);
  const int status_code = esp_http_client_get_status_code(client);
  esp_http_client_cleanup(client);
  free(auth_str);
  if (retry_access_token) {
    refresh_token();
    return https_with_hostname_path(path, method, input_data, output);
  }
  return status_code;
}

#define SCOPE_APPEND(scope, name)                                              \
  do {                                                                         \
    if (scope & scopes) {                                                      \
      string += write_separator ? separator : "";                              \
      write_separator = true;                                                  \
      string += name;                                                          \
    }                                                                          \
  } while (0)

static std::string scope_name(Netatmo::Scopes scopes, const char *separator) {
  std::string string = "";
  bool write_separator = false;
  SCOPE_APPEND(Netatmo::Scopes::ReadCamera, "read_camera");
  SCOPE_APPEND(Netatmo::Scopes::ReadPresence, "read_presence");
  SCOPE_APPEND(Netatmo::Scopes::ReadDoorbell, "read_doorbell");
  SCOPE_APPEND(Netatmo::Scopes::ReadSmokedetector, "Read_smokedetector");
  SCOPE_APPEND(Netatmo::Scopes::ReadMx, "read_mx");
  SCOPE_APPEND(Netatmo::Scopes::ReadMhs1, "read_mhs1");
  SCOPE_APPEND(Netatmo::Scopes::WriteCamera, "write_camera");
  SCOPE_APPEND(Netatmo::Scopes::WritePresence, "write_presence");
  SCOPE_APPEND(Netatmo::Scopes::WriteMx, "write_mx");
  return string;
}

#define GATEWAY_APPEND(gateway)                                                \
  do {                                                                         \
    if (Netatmo::GatewayTypes::gateway & gateway_type) {                       \
      string += write_separator ? separator : "";                              \
      write_separator = true;                                                  \
      string += #gateway;                                                      \
    }                                                                          \
  } while (0)

static std::string gateway_type_name(Netatmo::GatewayTypes gateway_type,
                                     const char *separator) {
  std::string string = "";
  bool write_separator = false;
  GATEWAY_APPEND(NACamera);
  GATEWAY_APPEND(NOC);
  GATEWAY_APPEND(NDB);
  GATEWAY_APPEND(NSD);
  GATEWAY_APPEND(NCO);
  GATEWAY_APPEND(BNCX);
  GATEWAY_APPEND(BNMH);
  return string;
}

void gen_random(char *string, const int size) {
  static const char alphanum[] = "0123456789"
                                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "abcdefghijklmnopqrstuvwxyz";
  for (int i = 0; i < size - 1; ++i) {
    string[i] = alphanum[esp_random() % (sizeof(alphanum) - 1)];
  }
}
