//Linux
#include <poll.h>

//openssl
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

//libc
#include <ctime>


//C++ STL
#include <sstream>
#include <iostream>
#include <map>
#include <string>

class Https_client{
    // openssl vars
    SSL_CTX * ssl_ctx = NULL;
    SSL * ssl = NULL;
    BIO * ssl_bio = NULL;
    
    // request vars
    std::string method {"GET"};
    std::string request{};
    std::string ressource {"/"};
    std::string host{};
    std::string req_body{};
    int port{443};
    std::map<std::string, std::string> request_headers{};
    
    // response
    std::string response{};
    
    // form data vars
    std::string multipart_boundary{"xhiehbabfjfbdbsggsv"};
    std::string multipart_boundary_quoted{"\"xhiehbabfjfbdbsggsv\""};
    std::map<std::string, std::string> request_multipart_form_data{};
    
    //timeout polling
    struct pollfd poll_fds[1];
    int timeout_milliseconds{1000};
    
    public:
    Https_client(const char * certificates_path){
        init_ssl_library();
        
        // create a "SSL context" with the "TLS client method"
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if(!ssl_ctx) {
            std::cerr << ("SSL_CTX_new error");
            ERR_print_errors_fp(stderr);
            exit(-1);
        }
        
        // some certicate verification options
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(ssl_ctx, 4);
        
        // some ssl options
        const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
        SSL_CTX_set_options(ssl_ctx, flags);
        
        // setting certicates paths
        int res = SSL_CTX_load_verify_locations(ssl_ctx, 0, certificates_path);
        if(!(1 == res)){
            std::cerr << "SSL_CTX_load_verify_locations error";
            ERR_print_errors_fp(stderr);
            exit(-1);
        }
        
        // create the SSL BIO (BIO + SSL layers)
        ssl_bio = BIO_new_ssl_connect(ssl_ctx);
        if(!ssl_bio){
            std::cerr << ("BIO_new_ssl_connect error");
            ERR_print_errors_fp(stderr);
            exit(-1);
        }
        
        // setup bio to close socker file descriptor when freed (not sure what the default is)
        BIO_set_close(ssl_bio, BIO_CLOSE);
        
        // aquire the ssl object from Bio to then set it up for prefered and unprefered ciphers.
        BIO_get_ssl(ssl_bio, &ssl);
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
        const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
        res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
        if(!(1 == res)){
            std::cerr << ("SSL_set_cipher_list error");
            ERR_print_errors_fp(stderr);
            exit(-1);
        }
    }
    std::string get_response(){
        return response;
    }
    std::string get_request(){
        return request;
    }
    void set_host(std::string h){
        host = h;
        request_headers["Host"] = host;
    }
    void set_port(int p){
        port = p;
    }
    void set_ressource(std::string res){
        ressource = res;
    }
    void set_method(std::string m){
        method = m;
    }
    void set_timeout_milliseconds(int timeout){
        timeout_milliseconds = timeout;
    }
    void set_header(std::string header, std::string value){
        request_headers[header] = value;
    }
    void set_form_data(std::string field_name, std::string value){
        request_multipart_form_data[field_name] = value;
    }
    std::string build_request(){
        if(!request_multipart_form_data.empty()){
            set_header("Content-Type", std::string("multipart/form-data;boundary=")+ multipart_boundary_quoted );
            std::stringstream ss_body{};
            for(const auto & fd: request_multipart_form_data){
            ss_body << "--" <<  multipart_boundary << "\r\n"
            << "Content-Disposition: form-data; name="
            << fd.first << "\r\n\r\n"
            << fd.second << "\r\n";
            }
            ss_body << "--" << multipart_boundary << "--\r\n\r\n";
            req_body = ss_body.str();
            set_header("Content-Length", std::to_string(req_body.size()));
        }
        std::stringstream ss;
        ss << std::noskipws << method
           << " " << ressource << " HTTP/1.1\r\n";
        for(const auto & p: request_headers){
            ss << p.first << ": " << p.second << "\r\n";
        }
        ss  <<  "\r\n" ;
        
        request = ss.str();
        request = request + req_body;
        
        return request;
    }
    
    std::string send_request(){
        
        // setting up hostname
        std::string host_and_port = host + std::string(":") + std::to_string(port);
        BIO_set_conn_hostname(ssl_bio, host_and_port.c_str());
        SSL_set_tlsext_host_name(ssl, host.c_str());
        
        // TCP handshake
        if(BIO_do_connect(ssl_bio)<=0){
            std::cerr << ("BIO_do_connect error");
            ERR_print_errors_fp(stderr);
            exit(-1);
        }
        
        // performs TLS handshake
        BIO_do_handshake(ssl_bio);
        
        // send request
        BIO_puts(ssl_bio, request.c_str());
        
        // prepare for response
        response = "";
        int total_bytes_read{0};
        
        // prepare for polling the socket file descriptor in while loop condition, so that BIO_read always has something to read, keeping in mind that BIO_read is blocking the execution and hangs if server connection still kept alive but server has finished sending data.
        poll_fds[0].fd = BIO_get_fd(ssl_bio,0);
        poll_fds[0].events = POLLIN;
        
        // reading loop
        while(BIO_pending(ssl_bio) || (poll(poll_fds,1,timeout_milliseconds)>0)){
            std::string read_buf(128,0);
            int bytes = BIO_read(ssl_bio, 
                         (char*)read_buf.data(),
                          read_buf.size());
            if (bytes <= 0) break;
            response = response + read_buf.substr(0,bytes);
            total_bytes_read += bytes;
        }
        response.resize(total_bytes_read);
        
        BIO_reset(ssl_bio);
        return response;
    }
    void init_ssl_library(){
        SSL_library_init();
        SSL_load_error_strings();
    }
    ~Https_client(){
        // cleanup
        SSL_CTX_free(ssl_ctx);
        BIO_free_all(ssl_bio);
    }
};






int main(){
    //start time
    std::cout << "start time: " << time(0) << std::endl;
    
    //create client with path to certificates directory
    Https_client client{"etc/ssl/certs/"};
    
    //get request
    client.set_host("example.com");
    client.set_ressource("/");
    client.set_method("GET");
    client.set_header("User-Agent", "Farts");
    client.set_header("Accept","*");
    client.set_header("Accept-Language","*");
    client.set_port(443);
    client.set_timeout_milliseconds(100);
    std::cout << client.build_request() << std::endl;
    std::cout << client.send_request() << std::endl;
    
    //post request with some form data
    client.set_host("httpbin.org");
    client.set_header("Connection","close");
    client.set_form_data("fname","Paul");
    client.set_form_data("telephone","2747388237");
    client.set_ressource("/post");
    client.set_method("POST");
    std::cout << client.build_request() << std::endl;
    std::cout << client.send_request() << std::endl;
    
    //end time
    std::cout << "end time: " << time(0) << std::endl;
    std::cout << "done" << std::endl;
    return 0;
}
