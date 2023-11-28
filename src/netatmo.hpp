#pragma once

#include <string>
#include <vector>

#include <cJSON.h>
#include <esp_http_client.h>

class Netatmo {
public:
  typedef enum GatewayTypes {
    None = 0,
    NACamera = 1 << 0,
    NOC = 1 << 1,
    NDB = 1 << 2,
    NSD = 1 << 3,
    NCO = 1 << 4,
    BNCX = 1 << 5,
    BNMH = 1 << 6
  } GatewayTypes;

  typedef enum Scopes {
    ReadCamera = 1 << 0,
    ReadPresence = 1 << 1,
    ReadDoorbell = 1 << 2,
    ReadSmokedetector = 1 << 3,
    ReadMx = 1 << 4,
    ReadMhs1 = 1 << 5,
    WriteCamera = 1 << 6,
    WritePresence = 1 << 7,
    WriteMx = 1 << 8
  } Scopes;

  int homes_data(const char *home_id, GatewayTypes gateaway_types,
                 cJSON **output);
  int home_status(const char *, GatewayTypes arr, cJSON **output);
  int get_events(const std::string &home_id, GatewayTypes gateaway_types,
                 const std::string &event_id, const std::string &person_id,
                 const std::string &device_id, const std::string &module_id,
                 int offset, int size, const std::string &locale,
                 cJSON **output);
  int set_persons_away(std::string home_id, std::string persone_id);
  int set_persons_home(std::string home_id,
                       std::vector<std::string> &persone_ids);
  int set_state(const cJSON *state);
  int add_webhook(std::string url);
  int drop_webhook();

  char *get_redirect_url(const char *redirectURI, Scopes scopes);
  bool check_state(const char *state);
  int request_token(const std::string code, const char *redirectURI,
                    Scopes scopes);
  int refresh_token();
  char *getaccess_token();
  char *getrefresh_token();

  static char unique_state[10];

protected:
  int inner_request_tokens(const char *path, const std::string &data);
  int https_with_hostname_path(const char *path,
                               esp_http_client_method_t method,
                               const cJSON *input, cJSON **output);
  void save_token(const char *access_token, const char *refresh_token);
};

inline Netatmo::Scopes operator|(Netatmo::Scopes a, Netatmo::Scopes b) {
  return static_cast<Netatmo::Scopes>(static_cast<int>(a) |
                                      static_cast<int>(b));
}

inline Netatmo::GatewayTypes operator|(Netatmo::GatewayTypes a,
                                       Netatmo::GatewayTypes b) {
  return static_cast<Netatmo::GatewayTypes>(static_cast<int>(a) |
                                            static_cast<int>(b));
}