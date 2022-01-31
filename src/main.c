#include <dc_application/command_line.h>
#include <dc_application/config.h>
#include <dc_application/options.h>
#include <dc_posix/dc_netdb.h>
#include <dc_posix/dc_stdlib.h>
#include <dc_posix/dc_string.h>
#include <dc_posix/dc_unistd.h>
#include <dc_posix/dc_time.h>
#include <dc_posix/sys/dc_socket.h>
#include <assert.h>
#include <getopt.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


struct application_settings
{
    struct dc_opt_settings opts;
    struct dc_setting_bool *verbose;
    struct dc_setting_regex *ip_version;
    struct dc_setting_string *hostname;
    struct dc_setting_uint16 *port;
    struct dc_setting_uint16 *min_chars;
    struct dc_setting_uint16 *max_chars;
    struct dc_setting_uint16 *min_delay;
    struct dc_setting_uint16 *max_delay;
    struct dc_setting_string *request_string;
};

static struct dc_application_settings *create_settings(const struct dc_posix_env *env, struct dc_error *err);
static int destroy_settings(const struct dc_posix_env *env,
                            struct dc_error *err,
                            struct dc_application_settings **psettings);
static int run(const struct dc_posix_env *env, struct dc_error *err, struct dc_application_settings *settings);
static int connect_to_server(const struct dc_posix_env *env,
                      struct dc_error *err,
                      const char *ip_version,
                      const char *hostname,
                      uint16_t port);
static void send_request(const struct dc_posix_env *env,
                 struct dc_error *err,
                 int socket_fd,
                 const char *message,
                 uint16_t min_chars,
                 uint16_t max_chars,
                 uint16_t min_delay,
                 uint16_t max_delay);

int main(int argc, char *argv[])
{
    dc_error_reporter reporter;
    dc_posix_tracer tracer;
    struct dc_posix_env env;
    struct dc_error err;
    struct dc_application_info *info;
    int ret_val;

    reporter = dc_error_default_error_reporter;
    tracer = dc_posix_default_tracer;
    tracer = NULL;
    dc_error_init(&err, reporter);
    dc_posix_env_init(&env, tracer);
    info = dc_application_info_create(&env, &err, "Settings Application");
    ret_val = dc_application_run(&env, &err, info, create_settings, destroy_settings, run, dc_default_create_lifecycle, dc_default_destroy_lifecycle, NULL, argc, argv);
    dc_application_info_destroy(&env, &info);
    dc_error_reset(&err);

    return ret_val;
}

static struct dc_application_settings *create_settings(const struct dc_posix_env *env, struct dc_error *err)
{
    struct application_settings *settings;
    static const bool default_verbose = false;
    static const char *default_ip = "IPv4";
    static const char *default_hostname = "localhost";
    static const uint16_t default_port = 80;
    static const uint16_t default_min_chars = 1;
    static const uint16_t default_max_chars = 1;
    static const uint16_t default_min_delay = 2500;
    static const uint16_t default_max_delay = 2500;
    static const char *default_request_string = NULL;

    DC_TRACE(env);
    settings = dc_malloc(env, err, sizeof(struct application_settings));

    if(settings == NULL)
    {
        return NULL;
    }

    settings->opts.parent.config_path = dc_setting_path_create(env, err);
    settings->request_string = dc_setting_string_create(env, err);

    settings->opts.parent.config_path = dc_setting_path_create(env, err);
    settings->verbose = dc_setting_bool_create(env, err);
    settings->ip_version = dc_setting_regex_create(env, err, "^IPv[4|6]");
    settings->hostname = dc_setting_string_create(env, err);
    settings->port = dc_setting_uint16_create(env, err);
    settings->request_string = dc_setting_string_create(env, err);
    settings->min_chars = dc_setting_uint16_create(env, err);
    settings->max_chars = dc_setting_uint16_create(env, err);
    settings->min_delay = dc_setting_uint16_create(env, err);
    settings->max_delay = dc_setting_uint16_create(env, err);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
    struct options opts[] =
            {
                    {(struct dc_setting *)settings->opts.parent.config_path, dc_options_set_path,   "config",         required_argument, 'f', "CONFIG",         dc_string_from_string, NULL,             dc_string_from_config, NULL},
                    {(struct dc_setting *)settings->verbose,                 dc_options_set_bool,   "verbose",        no_argument,       'v', "VERBOSE",        dc_flag_from_string,   "verbose",        dc_flag_from_config,   &default_verbose},
                    {(struct dc_setting *)settings->ip_version,              dc_options_set_regex,  "ip",             required_argument, 'i', "IP",             dc_string_from_string, "ip",             dc_string_from_config, default_ip},
                    {(struct dc_setting *)settings->hostname,                dc_options_set_string, "host",           required_argument, 'h', "HOST",           dc_string_from_string, "host",           dc_string_from_config, default_hostname},
                    {(struct dc_setting *)settings->port,                    dc_options_set_uint16, "port",           required_argument, 'p', "PORT",           dc_uint16_from_string, "port",           dc_uint16_from_config, &default_port},
                    {(struct dc_setting *)settings->min_chars,               dc_options_set_uint16, "min-chars",      required_argument, 'c', "MIN_CHARS",      dc_uint16_from_string, "min-chars",      dc_uint16_from_config, &default_min_chars},
                    {(struct dc_setting *)settings->max_chars,               dc_options_set_uint16, "max-chars",      required_argument, 'C', "MAX_CHARS",      dc_uint16_from_string, "max-chars",      dc_uint16_from_config, &default_max_chars},
                    {(struct dc_setting *)settings->min_delay,               dc_options_set_uint16, "min-delay",      required_argument, 'd', "MIN_DELAY",      dc_uint16_from_string, "min-delay",      dc_uint16_from_config, &default_min_delay},
                    {(struct dc_setting *)settings->max_delay,               dc_options_set_uint16, "max-delay",      required_argument, 'D', "MAX_DELAY",      dc_uint16_from_string, "min-delay",      dc_uint16_from_config, &default_max_delay},
                    {(struct dc_setting *)settings->request_string,          dc_options_set_string, "request-string", required_argument, 'r', "REQUEST_STRING", dc_string_from_string, "request-string", dc_string_from_config, default_request_string},
            };
#pragma GCC diagnostic pop

    // note the trick here - we use calloc and add 1 to ensure the last line is all 0/NULL
    settings->opts.opts_count = (sizeof(opts) / sizeof(struct options)) + 1;
    settings->opts.opts_size = sizeof(struct options);
    settings->opts.opts = dc_calloc(env, err, settings->opts.opts_count, settings->opts.opts_size);
    dc_memcpy(env, settings->opts.opts, opts, sizeof(opts));
    settings->opts.flags = "m:";
    settings->opts.env_prefix = "DC_EXAMPLE_";

    return (struct dc_application_settings *)settings;
}

static int destroy_settings(const struct dc_posix_env *env,
                            __attribute__((unused)) struct dc_error *err,
                            struct dc_application_settings **psettings)
{
    struct application_settings *app_settings;

    DC_TRACE(env);
    app_settings = (struct application_settings *)*psettings;
    dc_setting_string_destroy(env, &app_settings->request_string);
    dc_free(env, app_settings->opts.opts, app_settings->opts.opts_count);
    dc_free(env, *psettings, sizeof(struct application_settings));

    if(env->null_free)
    {
        *psettings = NULL;
    }

    return 0;
}

static int run(const struct dc_posix_env *env, struct dc_error *err, struct dc_application_settings *settings)
{
    struct application_settings *app_settings;
    const char *request_string;
    uint16_t    min_chars;
    uint16_t    max_chars;
    uint16_t    min_delay;
    uint16_t    max_delay;
    const char *ip_version;
    const char *hostname;
    uint16_t    port;
    int         socket_fd;

    DC_TRACE(env);

    app_settings = (struct application_settings *)settings;
    request_string = dc_setting_string_get(env, app_settings->request_string);

    if(request_string == NULL)
    {
        exit(1);
    }

    min_chars  = dc_setting_uint16_get(env, app_settings->min_chars);
    max_chars  = dc_setting_uint16_get(env, app_settings->max_chars);

    if(min_chars > max_chars)
    {
        exit(1);
    }

    min_delay = dc_setting_uint16_get(env, app_settings->min_delay);
    max_delay = dc_setting_uint16_get(env, app_settings->max_delay);

    if(min_delay > max_delay)
    {
        exit(1);
    }

    ip_version = dc_setting_regex_get(env, app_settings->ip_version);
    hostname   = dc_setting_string_get(env, app_settings->hostname);
    port       = dc_setting_uint16_get(env, app_settings->port);
    socket_fd = connect_to_server(env, err, ip_version, hostname, port);
    send_request(env, err, socket_fd, request_string, min_chars, max_chars, min_delay, max_delay);

    return EXIT_SUCCESS;
}

static int connect_to_server(const struct dc_posix_env *env,
                             struct dc_error *err,
                             const char *ip_version,
                             const char *hostname,
                             uint16_t port)
{
    int family;
    struct addrinfo hints;
    struct addrinfo *result;
    int sock_fd;
    uint16_t converted_port;
    socklen_t size;

    if(dc_strcmp(env, ip_version, "IPv4") == 0)
    {
        family = PF_INET;
    }
    else
    {
        if(dc_strcmp(env, ip_version, "IPv6") == 0)
        {
            family = PF_INET6;
        }
        else
        {
            assert("Can't get here" != NULL);
            family = 0;
        }
    }

    dc_memset(env, &hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    dc_getaddrinfo(env, err, hostname, NULL, &hints, &result);

    if(dc_error_has_error(err))
    {
        return -1;
    }

    sock_fd = dc_socket(env, err, result->ai_family, result->ai_socktype, result->ai_protocol);

    if(dc_error_has_error(err))
    {
        return -1;
    }

    // NOLINTNEXTLINE(hicpp-signed-bitwise)
    converted_port = htons(port);

    if(dc_strcmp(env, ip_version, "IPv4") == 0)
    {
        struct sockaddr_in *sockaddr;

        sockaddr = (struct sockaddr_in *)result->ai_addr;
        sockaddr->sin_port = converted_port;
        size = sizeof(struct sockaddr_in);
    }
    else
    {
        if(dc_strcmp(env, ip_version, "IPv6") == 0)
        {
            struct sockaddr_in6 *sockaddr;

            sockaddr = (struct sockaddr_in6 *)result->ai_addr;
            sockaddr->sin6_port = converted_port;
            size = sizeof(struct sockaddr_in);
        }
        else
        {
            assert("Can't get here" != NULL);
            size = 0;
        }
    }

    dc_connect(env, err, sock_fd, result->ai_addr, size);

    if(dc_error_has_error(err))
    {
        return -1;
    }

    return sock_fd;
}

static void send_request(const struct dc_posix_env *env,
                         struct dc_error *err,
                         int socket_fd,
                         const char *request,
                         uint16_t min_chars,
                         uint16_t max_chars,
                         uint16_t min_delay,
                         uint16_t max_delay)
{
    size_t length;
    char *full_request;
    struct timespec sleep_info;

    // + 4 for the trailing \r\n\r\n
    length = dc_strlen(env, request) + 4;
    full_request = dc_malloc(env, err, length);
    dc_strcpy(env, full_request, request);
    dc_strcat(env, full_request, "\r\n\r\n");

    for(size_t i = 0; i < length;)
    {
        size_t next;
        long delay;

        next = min_chars;
        delay = min_delay;

        if(i + next > length)
        {
            next = length - i;
        }

        dc_write(env, err, socket_fd, &full_request[i], next);
        dc_write(env, err, STDOUT_FILENO, "SENT: ", 6);
        dc_write(env, err, STDOUT_FILENO, &full_request[i], next);
        dc_write(env, err, STDOUT_FILENO, "\n", 1);
        sleep_info.tv_sec = 0L;
        sleep_info.tv_nsec = delay * 100000L;
        dc_nanosleep(env, err, &sleep_info, NULL);
        i += next;
    }

    // TODO: need to loop over this
    char buffer[2048];
    ssize_t nread;

    nread = dc_read(env, err, socket_fd, buffer, 2048);
    dc_write(env, err, STDOUT_FILENO, buffer, nread);
}
