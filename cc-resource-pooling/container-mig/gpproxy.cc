#include <dlfcn.h>
#include <stdio.h>
#include <iostream>
#include <memory>
#include <string>
#include <fstream>
#include <chrono>
#include <cmath>
#include <map>
#include <exception>
#include <iomanip>
#include <thread>
#include <pthread.h>
#include <openssl/sha.h>
#include <grpc/support/log.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "gt.grpc.pb.h"
#include "gt.pb.h"

#include "gpproxy.h"

extern "C" {
#include "dbusc_gpw.h"
}

#include "dbusc_jwt.h"
#include "yaml-cpp/yaml.h"


using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::ServerCompletionQueue;
using grpc::ServerAsyncResponseWriter;
using grpc::ServerAsyncReader;

using grpc::experimental::AltsServerCredentials;
using grpc::experimental::AltsServerCredentialsOptions;

using gt::gpp;
using gt::Inicont_Request;
using gt::Inicont_Reply;
using gt::Fincont_Request;
using gt::Fincont_Reply;
using gt::Opes_Reply;
using gt::Opes_Request;
using gt::Close_Reply;
using gt::Close_Request;
using gt::Invo_Reply;
using gt::Invo_Request;
using gt::TA_Chunk;
using gt::TA_Reply;
using gt::Setjwt_Request;
using gt::Setjwt_Reply;
using gt::LT_Request;
using gt::LT_Reply;

#define NO_ERROR 0

std::string global_strcfgfiletemp = getenv("HOME");
std::string global_strcfgfile = global_strcfgfiletemp + "/.gpp/gpproxy_config.yaml";
YAML::Node glo_config = YAML::LoadFile(global_strcfgfile);
std::string gpproxy_address = glo_config["GPPROXY_ADDRESS"].as<std::string>();
std::string global_servercert_path =
      global_strcfgfiletemp + "/.gpp/certs/" + glo_config["NAME_SERVER_CERT"].as<std::string>();
std::string global_serverkey_path =
      global_strcfgfiletemp + "/.gpp/certs/" + glo_config["NAME_SERVER_KEY"].as<std::string>();
std::string global_clientcacert_path =
      global_strcfgfiletemp + "/.gpp/certs/" + glo_config["NAME_CLIENTCA_CERT"].as<std::string>();
int grpc_tls = glo_config["GRPC_TLS"].as<int>();
int global_force_valideta_jwt = glo_config["FORCE_VALIDATE_JWT"].as<int>();

int global_max_num_thread = glo_config["MAX_NUM_THREAD"].as<int>();
int global_max_num_worker = glo_config["MAX_NUM_WORKER"].as<int>();
int global_timeout_session = glo_config["TIMEDOUT_SESSION"].as<int>();
int global_timeout_context = glo_config["TIMEDOUT_CONTEXT"].as<int>();


static std::string get_file_contents(std::string fpath)
{
   std::ifstream finstream(fpath);
   std::string contents;
   contents.assign((std::istreambuf_iterator<char>(finstream)),
                   std::istreambuf_iterator<char>());
   finstream.close();
   return contents;
}

bool utf8_check_is_valid(std::string &string)
{
   int c, i, ix, n, j;
   for (i = 0, ix = string.length(); i < ix; i++)
   {
      c = (unsigned char) string[i];
      //if (c==0x09 || c==0x0a || c==0x0d || (0x20 <= c && c <= 0x7e) ) n = 0; // is_printable_ascii
      if (0x00 <= c && c <= 0x7f) n = 0; // 0bbbbbbb
      else if ((c & 0xE0) == 0xC0) n = 1; // 110bbbbb
      else if (c == 0xed && i < (ix - 1) && ((unsigned char) string[i + 1] & 0xa0) == 0xa0)
         return false; //U+d800 to U+dfff
      else if ((c & 0xF0) == 0xE0) n = 2; // 1110bbbb
      else if ((c & 0xF8) == 0xF0) n = 3; // 11110bbb
         //else if (($c & 0xFC) == 0xF8) n=4; // 111110bb //byte 5, unnecessary in 4 byte UTF-8
         //else if (($c & 0xFE) == 0xFC) n=5; // 1111110b //byte 6, unnecessary in 4 byte UTF-8
      else return false;
      for (j = 0; j < n && i < ix; j++)
      { // n bytes matching 10bbbbbb follow ?
         if ((++i == ix) || (((unsigned char) string[i] & 0xC0) != 0x80))
            return false;
      }
   }
   return true;
}


#define MAX_DATA_LEN 50*1024
#define SHA256_LENTH 32

int get_file_sha256(char *file_path, char *val)
{
   SHA256_CTX sha256_ctx;
   FILE *fp = NULL;
   char *strFilePath = file_path;
   unsigned char SHA256result[SHA256_LENTH];
   char DataBuff[MAX_DATA_LEN];
   int len;
   int t = 0;
   int i;
   std::string sha256;

   fp = fopen(strFilePath, "rb");

   SHA256_Init(&sha256_ctx);

   while (!feof(fp))
   {
      memset(DataBuff, 0x00, sizeof(DataBuff));

      len = fread(DataBuff, 1, MAX_DATA_LEN, fp);
      if (len)
      {
         t += len;
         SHA256_Update(&sha256_ctx, DataBuff, len);
      }
   }

   fclose(fp);
   SHA256_Final(SHA256result, &sha256_ctx);

   if (val == NULL || (sizeof(val) * 4) < SHA256_LENTH)
   {
      return -1;
   } else
   {
      memset(val, 0, sizeof(val));
      memcpy(val, SHA256result, SHA256_LENTH);
   }

   return 0;
}

bool isFileExists_ifstream(std::string &name)
{
   std::ifstream f(name.c_str());
   return f.good();
}

void check_config()
{
   if (grpc_tls != 0 && grpc_tls != 1 && grpc_tls != 2)
   {
      std::cout << global_strcfgfile << " grpc_tls should be 0 or 1 or 2 " << std::endl;
      exit(-1);
   }
   if (global_force_valideta_jwt != 0 && global_force_valideta_jwt != 1)
   {
      std::cout << global_strcfgfile << " global_force_valideta_jwt should be 0 or 1 " << std::endl;
      exit(-1);
   }
   if (global_max_num_thread < 0 || global_max_num_thread > 128)
   {
      std::cout << global_strcfgfile << " global_max_num_thread should between 0 and 128 " << std::endl;
      exit(-1);
   }
   if (global_max_num_worker < 0 || global_max_num_worker > 128)
   {
      std::cout << global_strcfgfile << " global_max_num_worker should between 0 and 128 " << std::endl;
      exit(-1);
   }
   if (global_timeout_session <= 0)
   {
      std::cout << global_strcfgfile << " global_timeout_session should > 0 " << std::endl;
      exit(-1);
   }
   if (global_timeout_context <= 0)
   {
      std::cout << global_strcfgfile << " global_timeout_context should > 0 " << std::endl;
      exit(-1);
   }
   if (grpc_tls == 2)
   {
      if (!isFileExists_ifstream(global_servercert_path))
      {
         std::cout << "error file : " << global_servercert_path << " is not exist " << std::endl;
         exit(-1);
      }
      if (!isFileExists_ifstream(global_serverkey_path))
      {
         std::cout << "error file : " << global_serverkey_path << " is not exist " << std::endl;
         exit(-1);
      }
      if (!isFileExists_ifstream(global_clientcacert_path))
      {
         std::cout << "error file : " << global_clientcacert_path << " is not exist " << std::endl;
         exit(-1);
      }
   }
   if (grpc_tls == 1)
   {
      if (!isFileExists_ifstream(global_servercert_path))
      {
         std::cout << "error file : " << global_servercert_path << " is not exist " << std::endl;
         exit(-1);
      }
      if (!isFileExists_ifstream(global_serverkey_path))
      {
         std::cout << "error file : " << global_serverkey_path << " is not exist " << std::endl;
         exit(-1);
      }
   }
}

class ServerImpl final
{
public:
    ~ServerImpl()
    {
       server_->Shutdown();
       for (auto &cq: cq_)
          cq->Shutdown();
       delete[] workerrec;
       delete[] ltworkerrec;
    }

    ServerImpl()
    {
       pthread_mutex_init(&mutex_workerrec, NULL);
       pthread_cond_init(&cond_notbusy, NULL);
       for (int iworker = 0; iworker < global_max_num_worker; iworker++)
       {
          workerrec[iworker].busy = 0;
          workerrec[iworker].context_fd = 0;
          workerrec[iworker].context_addr = 0xffffffff;
          workerrec[iworker].sessionid_count = 0;
          workerrec[iworker].first = NULL;
          workerrec[iworker].last = NULL;
       }
       for (int iworker = 0; iworker < global_max_num_worker; iworker++)
       {
          ltworkerrec[iworker].busy = 0;
          ltworkerrec[iworker].context_fd = 0;
          ltworkerrec[iworker].context_addr = 0xffffffff;
          ltworkerrec[iworker].sessionid_count = 0;
          ltworkerrec[iworker].first = NULL;
          ltworkerrec[iworker].last = NULL;
       }
    }

    class CallData
    {

    public:

        enum ServiceType
        {
            SS_TEECC_InitializeContext = 0,
            SS_TEECC_FinalizeContext = 1,
            SS_TEECC_OpenSession = 2,
            SS_TEECC_CloseSession = 3,
            SS_TEECC_InvokeCommand = 4,
            SS_TEECC_TA = 5,
            SS_TEECC_SetJwt = 6,
            SS_TEECC_LiveTransfer = 7
        };

        ~CallData()
        {

        }

        CallData(gpp::AsyncService *service,
                 ServerCompletionQueue *cq,
                 ServiceType s_type,
                 pthread_mutex_t *mutex_workerrec,
                 pthread_cond_t *cond_notbusy,
                 wr_t *workerrec,
                 wr_t *ltworkerrec)
              : service_(service),
                cq_(cq),
                s_type_(s_type),
                mutex_workerrec_(mutex_workerrec),
                cond_notbusy_(cond_notbusy),
                workerrec_(workerrec),
                ltworkerrec_(ltworkerrec),
                inicont_response(&ctx_),
                fincont_response(&ctx_),
                opes_response(&ctx_),
                close_response(&ctx_),
                invo_response(&ctx_),
                ta_response(&ctx_),
                setjwt_response(&ctx_),
                lt_response(&ctx_),
                status_(CREATE)
        {
           Process();
        }

        void Process()
        {
           if (status_ == CREATE)
           {
              status_ = PROCESS;
              switch (s_type_)
              {
                 case ServerImpl::CallData::SS_TEECC_InitializeContext:
                    service_->RequestTEECC_InitializeContext(&ctx_, &inicont_request, &inicont_response, cq_, cq_,
                                                             this);
                    break;
                 case ServerImpl::CallData::SS_TEECC_FinalizeContext:
                    service_->RequestTEECC_FinalizeContext(&ctx_, &fincont_request, &fincont_response, cq_, cq_, this);
                    break;
                 case ServerImpl::CallData::SS_TEECC_OpenSession:
                    service_->RequestTEECC_OpenSession(&ctx_, &opes_request, &opes_response, cq_, cq_, this);
                    break;
                 case ServerImpl::CallData::SS_TEECC_InvokeCommand:
                    service_->RequestTEECC_InvokeCommand(&ctx_, &invo_request, &invo_response, cq_, cq_, this);
                    break;
                 case ServerImpl::CallData::SS_TEECC_CloseSession:
                    service_->RequestTEECC_CloseSession(&ctx_, &close_request, &close_response, cq_, cq_, this);
                    break;
                 case ServerImpl::CallData::SS_TEECC_TA:
                    service_->RequestTEECC_TA(&ctx_, &ta_chunk, &ta_response, cq_, cq_, this);
                    break;
                 case ServerImpl::CallData::SS_TEECC_SetJwt:
                    service_->RequestTEECC_SetJwt(&ctx_, &setjwt_request, &setjwt_response, cq_, cq_, this);
                    break;
                 case ServerImpl::CallData::SS_TEECC_LiveTransfer:
                    service_->RequestTEECC_LiveTransfer(&ctx_, &lt_request, &lt_response, cq_, cq_, this);
                    break;

                 default:
                    break;
              }

           } else if (status_ == PROCESS)
           {
              status_ = FINISH;
              new CallData(service_, cq_, this->s_type_, mutex_workerrec_, cond_notbusy_, workerrec_,ltworkerrec_);

              switch (s_type_)
              {
                 case ServerImpl::CallData::SS_TEECC_InitializeContext:
                 {
                    struct timeval start, end, jwt_validate_start, jwt_validate_end;
                    gettimeofday(&start, NULL);

                    std::string name;
                    const uint8_t *name_temp = reinterpret_cast<const uint8_t *>(name.c_str());
                    std::size_t name_size;
                    std::int32_t in_context_fd;
                    std::string in_context_tapath;
                    const uint8_t *in_context_tapath_temp = NULL;
                    std::int32_t in_context_tapath_size;
                    unsigned char *charp = NULL;
                    std::string charpp;
                    std::uint64_t in_context_sessionlist_next;
                    std::uint64_t in_context_sessionlist_prev;
                    std::uint64_t in_context_shrdmemlist_next;
                    std::uint64_t in_context_shrdmemlist_prev;
                    std::uint64_t in_context_sharebuffer_buffer;
                    std::int64_t in_context_sharebuffer_bufferbarrier;

                    std::uint32_t teecresult;
                    std::int32_t fd;

                    unsigned char *ta_path = NULL;
                    std::int32_t ta_path_size = 0;

                    std::uint64_t session_list_next;
                    std::uint64_t session_list_prev;
                    std::uint64_t shrd_mem_list_next;
                    std::uint64_t shrd_mem_list_prev;
                    std::uint64_t share_buffer_buffer;
                    std::int64_t share_buffer_buffer_barrier;
                    std::uint64_t context_addr;

                    in_context_fd = 0;
                    in_context_tapath_size = 0;
                    in_context_sessionlist_next = 0;
                    in_context_sessionlist_prev = 0;
                    in_context_shrdmemlist_next = 0;
                    in_context_shrdmemlist_prev = 0;
                    in_context_sharebuffer_buffer = 0;
                    in_context_sharebuffer_bufferbarrier = 0;

                    name_size = inicont_request.name_size();
                    if (name_size > 0)
                    {
                       name = inicont_request.name();
                       std::cout << "gpp received name: " << name << std::endl;
                    }

                    std::uint32_t serial = 0;
                    std::int32_t flag = 0;

                    std::string token;
                    token = inicont_request.token();

                    std::string noToken("noToken");
                    int ivaljwtResult = -1;
                    int iforceValidateJwt = global_force_valideta_jwt;

                    if
                          (
                          iforceValidateJwt == 1
                          &&
                          token.compare(noToken) != 0
                          )
                    {
                       char Token[1024];
                       strcpy(Token, (char *) token.data());

                       gettimeofday(&jwt_validate_start, NULL);
                       ivaljwtResult =
                             dbusmethodcall_validate_jwt(
                                   Token
                             );
                       gettimeofday(&jwt_validate_end, NULL);
                       int64_t i64Time_jwt;
                       i64Time_jwt = (jwt_validate_end.tv_sec - jwt_validate_start.tv_sec) * 1000000 +
                                     (jwt_validate_end.tv_usec - jwt_validate_start.tv_usec);
                       printf("gpp initcont validate jwt used time: %ld us. \n", i64Time_jwt);

                       std::cout << "gpp validate initcont jwtsvid" << std::endl;
                    } else
                    {
                       std::cout << "gpp no validate initcont jwtsvid" << std::endl;
                    }

                    if
                          (
                          iforceValidateJwt != 1
                          ||
                          (
                                iforceValidateJwt == 1
                                &&
                                token.compare(noToken) != 0
                                &&
                                ivaljwtResult == NO_ERROR
                          )
                          )
                    {
                       std::cout << "gpp does not need validate initcont jwtsvid or validate jwt succed" << std::endl;
                       std::cout << "gpp received init context" << std::endl;
                       std::cout << "gpp received namesize: " << name_size << std::endl;

                       ta_path = (unsigned char *) malloc(1024 * sizeof(char));
                       ta_path_size = 1024;
                       memset((char *) ta_path, 0, 1024);
                       uint32_t context_tapath_outsize;

                       char workername[1024];
                       memset((char *) workername, 0, 1024);
                       int ifound = 0;
                       int iworker;

                       for (;;)
                       {
                          pthread_mutex_lock(mutex_workerrec_);
                          for (iworker = 0; iworker < global_max_num_worker; iworker++)
                          {
                             if (workerrec_[iworker].busy == 0)
                             {
                                sprintf(workername, "%s%d", "gpworker", iworker);
                                std::cout << "gpp method call worker No: " << std::dec << iworker << std::endl;
                                workerrec_[iworker].busy = 1;
                                ifound = 1;
                                break;
                             }
                          }
                          if (ifound == 0)
                          {
                             pthread_cond_wait(cond_notbusy_, mutex_workerrec_);
                          }
                          pthread_mutex_unlock(mutex_workerrec_);

                          if (ifound == 1)
                          {
                             break;
                          }
                       }

                       method_call_teec_inicont(
                             workername,

                             name_temp,
                             name_size,
                             in_context_fd,
                             in_context_tapath_temp,
                             in_context_tapath_size,
                             in_context_sessionlist_next,
                             in_context_sessionlist_prev,
                             in_context_shrdmemlist_next,
                             in_context_shrdmemlist_prev,
                             in_context_sharebuffer_buffer,
                             in_context_sharebuffer_bufferbarrier,

                             &teecresult,

                             &fd,
                             ta_path,
                             ta_path_size,
                             &session_list_next,
                             &session_list_prev,
                             &shrd_mem_list_next,
                             &shrd_mem_list_prev,
                             &share_buffer_buffer,
                             &share_buffer_buffer_barrier,
                             &context_addr,
                             &context_tapath_outsize
                       );

                       if (teecresult == 0)
                       {
                          pthread_mutex_lock(mutex_workerrec_);
                          workerrec_[iworker].context_fd = fd;
                          workerrec_[iworker].context_addr = context_addr;
                          workerrec_[iworker].first = NULL;
                          workerrec_[iworker].last = NULL;
                          workerrec_[iworker].sessionid_count = 0;
                          struct timeval tvcreate;
                          gettimeofday(&tvcreate, NULL);
                          workerrec_[iworker].context_createtime = tvcreate;
                          pthread_mutex_unlock(mutex_workerrec_);
                       } else
                       {
                          workerrec_[iworker].busy = 0;
                       }

                       if (ta_path_size >= context_tapath_outsize)
                       {
                          ta_path_size = context_tapath_outsize;
                          charp = ta_path;
                       } else
                       {
                          ta_path_size = 0;
                          charp = NULL;
                       }
                       inicont_reply.set_teecresult(teecresult);
                       inicont_reply.set_context_fd(fd);
                       inicont_reply.set_context_tapath_outsize(ta_path_size);

                       if (ta_path_size > 0 &&
                           charp != NULL &&
                           strlen((const char *) charp) > 0
                             )
                       {
                          charpp = (const char *) charp;
                          if (utf8_check_is_valid(charpp))
                          {
                             ta_path_size = strlen((const char *) charp);
                          } else
                          {
                             ta_path_size = 0;
                          }
                       } else
                       {
                          ta_path_size = 0;
                       }
                       if (ta_path_size > 0)
                       {
                          inicont_reply.set_context_tapath(charpp);
                       }

                       inicont_reply.set_context_sessionlist_next(session_list_next);
                       inicont_reply.set_context_sessionlist_prev(session_list_prev);
                       inicont_reply.set_context_shrdmemlist_prev(shrd_mem_list_prev);
                       inicont_reply.set_context_shrdmemlist_next(shrd_mem_list_next);
                       inicont_reply.set_context_sharebuffer_buffer(share_buffer_buffer);
                       inicont_reply.set_context_sharebuffer_bufferbarrier(share_buffer_buffer_barrier);
                       inicont_reply.set_context_addr(context_addr);

                       status_ = FINISH;
                       gettimeofday(&end, NULL);
                       int64_t i64Time;
                       i64Time = (end.tv_sec - start.tv_sec) * 1000000 +
                                 (end.tv_usec - start.tv_usec);
                       printf("gpp initcont used time: %ld us. \n", i64Time);

                       inicont_response.Finish(inicont_reply, Status::OK, this);
                    } else
                    {
                       std::cout << "gpp receive no initcont jwtsvid or validate jwt failed" << std::endl;
                       flag = 2;
                       inicont_reply.set_flag(flag);
                       status_ = FINISH;

                       inicont_response.Finish(inicont_reply, Status::OK, this);
                    }
                    break;
                 }

                 case ServerImpl::CallData::SS_TEECC_FinalizeContext:
                 {
                    struct timeval start, end, jwt_validate_start, jwt_validate_end;
                    gettimeofday(&start, NULL);

                    std::int32_t in_context_fd;
                    std::string in_context_tapath;
                    const uint8_t *in_context_tapath_temp = NULL;
                    std::int32_t in_context_tapath_size;
                    unsigned char *charp = NULL;
                    std::string charpp;
                    std::uint64_t in_context_sessionlist_next;
                    std::uint64_t in_context_sessionlist_prev;
                    std::uint64_t in_context_shrdmemlist_next;
                    std::uint64_t in_context_shrdmemlist_prev;
                    std::uint64_t in_context_sharebuffer_buffer;
                    std::int64_t in_context_sharebuffer_bufferbarrier;
                    std::uint64_t in_context_addr;

                    std::uint32_t teecresult;
                    std::int32_t fd;

                    unsigned char *ta_path = NULL;
                    std::int32_t ta_path_size = 0;

                    std::uint64_t session_list_next;
                    std::uint64_t session_list_prev;
                    std::uint64_t shrd_mem_list_next;
                    std::uint64_t shrd_mem_list_prev;
                    std::uint64_t share_buffer_buffer;
                    std::int64_t share_buffer_buffer_barrier;

                    std::uint32_t serial = 0;
                    std::int32_t flag = 0;
                    std::string token;
                    token = fincont_request.token();
                    std::string noToken("noToken");
                    int ivaljwtResult = -1;
                    int iforceValidateJwt = global_force_valideta_jwt;
                    if
                          (
                          iforceValidateJwt == 1
                          &&
                          token.compare(noToken) != 0
                          )
                    {
                       char Token[1024];
                       strcpy(Token, (char *) token.data());

                       gettimeofday(&jwt_validate_start, NULL);
                       ivaljwtResult =
                             dbusmethodcall_validate_jwt(
                                   Token
                             );
                       gettimeofday(&jwt_validate_end, NULL);
                       int64_t i64Time_jwt;
                       i64Time_jwt = (jwt_validate_end.tv_sec - jwt_validate_start.tv_sec) * 1000000 +
                                     (jwt_validate_end.tv_usec - jwt_validate_start.tv_usec);
                       printf("gpp finacont validate jwt used time: %ld us. \n", i64Time_jwt);

                       std::cout << "gpp validate finacont jwtsvid" << std::endl;
                    } else
                    {
                       std::cout << "gpp no validate finacont jwtsvid" << std::endl;
                    }

                    if
                          (
                          iforceValidateJwt != 1
                          ||
                          (
                                iforceValidateJwt == 1
                                &&
                                token.compare(noToken) != 0
                                &&
                                ivaljwtResult == NO_ERROR
                          )
                          )
                    {
                       std::cout << "gpp does not need validate finacont jwtsvid or validate jwt succed" << std::endl;
                       std::cout << "gpp received fincontext" << std::endl;
                       in_context_fd = fincont_request.in_context_fd();
                       in_context_tapath_size = fincont_request.in_context_tapath_size();
                       if (in_context_tapath_size > 0)
                       {
                          in_context_tapath = fincont_request.in_context_tapath();
                          in_context_tapath_temp = reinterpret_cast<const uint8_t *>(in_context_tapath.c_str());
                          std::cout << "gpp received in_context_tapath_temp: " << in_context_tapath_temp
                                    << std::endl;
                       }

                       std::cout << "gpp received in_context_fd: " << in_context_fd << std::endl;
                       in_context_sessionlist_next = fincont_request.in_context_sessionlist_next();
                       in_context_sessionlist_prev = fincont_request.in_context_sessionlist_prev();
                       in_context_shrdmemlist_next = fincont_request.in_context_shrdmemlist_next();
                       in_context_shrdmemlist_prev = fincont_request.in_context_shrdmemlist_prev();
                       in_context_sharebuffer_buffer = fincont_request.in_context_shrdmemlist_prev();
                       in_context_sharebuffer_bufferbarrier = fincont_request.in_context_sharebuffer_bufferbarrier();
                       in_context_addr = fincont_request.in_context_addr();


                       ta_path = (unsigned char *) malloc(1024 * sizeof(char));
                       ta_path_size = 1024;
                       memset((char *) ta_path, 0, 1024);
                       uint32_t context_tapath_outsize;

                       char workername[1024];
                       memset((char *) workername, 0, 1024);
                       int ifound = 0;
                       int iworker;
                       pthread_mutex_lock(mutex_workerrec_);
                       for (iworker = 0; iworker < global_max_num_worker; iworker++)
                       {
                          if (workerrec_[iworker].context_fd == in_context_fd &&
                              workerrec_[iworker].context_addr == in_context_addr
                                )
                          {
                             sprintf(workername, "%s%d", "gpworker", iworker);
                             std::cout << "gpp method call worker No: " << std::dec << iworker << std::endl;
                             ifound = 1;
                             break;
                          }
                       }
                       pthread_mutex_unlock(mutex_workerrec_);

                       if (ifound == 0)
                       {
                          printf("gpp can't find the worker for the context. \n");

                          fd = 0;
                          ta_path_size = 0;
                          charp = NULL;
                          session_list_prev = 0;
                          shrd_mem_list_next = 0;
                          shrd_mem_list_prev = 0;
                          share_buffer_buffer = 0;
                          share_buffer_buffer_barrier = 0;

                          fincont_reply.set_context_fd(fd);
                          fincont_reply.set_context_tapath_outsize(ta_path_size);
                          fincont_reply.set_context_sessionlist_prev(session_list_prev);
                          fincont_reply.set_context_shrdmemlist_prev(shrd_mem_list_prev);
                          fincont_reply.set_context_shrdmemlist_next(shrd_mem_list_next);
                          fincont_reply.set_context_sharebuffer_buffer(share_buffer_buffer);
                          fincont_reply.set_context_sharebuffer_bufferbarrier(share_buffer_buffer_barrier);

                          status_ = FINISH;

                          fincont_response.Finish(fincont_reply, Status::OK, this);
                       } else
                       {
                          pthread_mutex_unlock(mutex_workerrec_);
                          sin_t *sinIns = NULL;
                          sin_t *sinInsPrev = NULL;
                          sinIns = workerrec_[iworker].last;
                          if (sinIns != NULL)
                          {
                             uint32_t in_session_seesionid;
                             uint32_t in_session_serviceid_timelow = 0;
                             uint32_t in_session_serviceid_timemid = 0;
                             uint32_t in_session_serviceid_timehiandver = 0;
                             uint32_t in_session_serviceid_clockseqandnode_size = 8;
                             uint32_t in_session_serviceid_clockseqandnode[8];
                             uint32_t in_session_opscnt = 0;
                             uint64_t in_session_head_next = 0;
                             uint64_t in_session_head_prev = 0;
                             uint64_t in_session_context;

                             uint32_t seesionid;
                             uint32_t serviceid_timelow;
                             uint32_t serviceid_timemid;
                             uint32_t serviceid_timehiandver;
                             uint32_t *serviceid_clockseqandnode;
                             int serviceid_clockseqandnode_realsize;
                             uint32_t opscnt;
                             uint64_t head_next;
                             uint64_t head_prev;
                             uint64_t session_context;

                             for (;;)
                             {
                                in_session_seesionid = sinIns->session_id;
                                in_session_context = workerrec_[iworker].context_addr;

                                pthread_mutex_unlock(mutex_workerrec_);

                                for (int iind = 0; iind < 8; iind++)
                                {
                                   in_session_serviceid_clockseqandnode[iind] = 0;
                                }

                                uint32_t serviceid_clockseqandnode_outsize_temp;
                                serviceid_clockseqandnode_realsize = 8;
                                serviceid_clockseqandnode =
                                      (uint32_t *) malloc(
                                            serviceid_clockseqandnode_realsize * sizeof(uint32_t)
                                      );

                                printf("\ngpp self method call teec closesession before finalizecontext \n");
                                method_call_teec_closesession(
                                      workername,

                                      in_session_seesionid,
                                      in_session_serviceid_timelow,
                                      in_session_serviceid_timemid,
                                      in_session_serviceid_timehiandver,
                                      in_session_serviceid_clockseqandnode,
                                      in_session_serviceid_clockseqandnode_size,
                                      in_session_opscnt,
                                      in_session_head_next,
                                      in_session_head_prev,
                                      in_session_context,

                                      &seesionid,
                                      &serviceid_timelow,
                                      &serviceid_timemid,
                                      &serviceid_timehiandver,
                                      serviceid_clockseqandnode,
                                      serviceid_clockseqandnode_realsize,
                                      &serviceid_clockseqandnode_outsize_temp,
                                      &opscnt,
                                      &head_next,
                                      &head_prev,
                                      &session_context
                                );

                                if (serviceid_clockseqandnode != NULL)
                                {
                                   free(serviceid_clockseqandnode);
                                }

                                pthread_mutex_lock(mutex_workerrec_);

                                sinInsPrev = sinIns->prev;
                                free(sinIns);
                                if (sinInsPrev == NULL)
                                {
                                   break;
                                }
                                sinIns = sinInsPrev;
                             }
                          }
                          pthread_mutex_unlock(mutex_workerrec_);

                          method_call_teec_fincont(
                                workername,

                                in_context_fd,
                                in_context_tapath_temp,
                                in_context_tapath_size,
                                in_context_sessionlist_next,
                                in_context_sessionlist_prev,
                                in_context_shrdmemlist_next,
                                in_context_shrdmemlist_prev,
                                in_context_sharebuffer_buffer,
                                in_context_sharebuffer_bufferbarrier,
                                in_context_addr,

                                &fd,
                                ta_path,
                                ta_path_size,
                                &session_list_next,
                                &session_list_prev,
                                &shrd_mem_list_next,
                                &shrd_mem_list_prev,
                                &share_buffer_buffer,
                                &share_buffer_buffer_barrier,
                                &context_tapath_outsize
                          );

                          pthread_mutex_lock(mutex_workerrec_);
                          workerrec_[iworker].busy = 0;
                          pthread_cond_signal(cond_notbusy_);
                          workerrec_[iworker].context_fd = 0;
                          workerrec_[iworker].context_addr = 0xffffffff;
                          workerrec_[iworker].sessionid_count = 0;
                          workerrec_[iworker].first = NULL;
                          workerrec_[iworker].last = NULL;
                          pthread_mutex_unlock(mutex_workerrec_);

                          if (ta_path_size >= context_tapath_outsize)
                          {
                             ta_path_size = context_tapath_outsize;
                             charp = ta_path;
                          } else
                          {
                             ta_path_size = 0;
                             charp = NULL;
                          }
                          fincont_reply.set_context_fd(fd);
                          fincont_reply.set_context_tapath_outsize(ta_path_size);

                          if (ta_path_size > 0 &&
                              charp != NULL &&
                              strlen((const char *) charp) > 0
                                )
                          {
                             charpp = (const char *) charp;
                             if (utf8_check_is_valid(charpp))
                             {
                                ta_path_size = strlen((const char *) charp);
                             } else
                             {
                                ta_path_size = 0;
                             }
                          } else
                          {
                             ta_path_size = 0;
                          }
                          if (ta_path_size > 0)
                          {
                             fincont_reply.set_context_tapath(charpp);
                          }

                          fincont_reply.set_context_sessionlist_next(session_list_next);
                          fincont_reply.set_context_sessionlist_prev(session_list_prev);
                          fincont_reply.set_context_shrdmemlist_prev(shrd_mem_list_prev);
                          fincont_reply.set_context_shrdmemlist_next(shrd_mem_list_next);
                          fincont_reply.set_context_sharebuffer_buffer(share_buffer_buffer);
                          fincont_reply.set_context_sharebuffer_bufferbarrier(share_buffer_buffer_barrier);

                          status_ = FINISH;
                          gettimeofday(&end, NULL);
                          int64_t i64Time;
                          i64Time = (end.tv_sec - start.tv_sec) * 1000000 +
                                    (end.tv_usec - start.tv_usec);
                          printf("gpp finalcontext used time: %ld us. \n", i64Time);

                          fincont_response.Finish(fincont_reply, Status::OK, this);
                       }
                    }else
                    {
                       std::cout << "gpp receive no finacont jwtsvid or validate jwt failed" << std::endl;
                       flag = 2;
                       fincont_reply.set_flag(flag);
                       status_ = FINISH;
                       fincont_response.Finish(fincont_reply, Status::OK, this);
                    }
                    break;
                 }

                 case ServerImpl::CallData::SS_TEECC_OpenSession:
                 {
                    struct timeval start, end, jwt_validate_start, jwt_validate_end;
                    gettimeofday(&start, NULL);

                    std::int32_t in_context_fd;
                    std::string in_context_tapath;
                    const uint8_t *in_context_tapath_temp = NULL;
                    std::int32_t in_context_tapath_size;
                    unsigned char *charp = NULL;
                    std::string charpp;
                    std::uint64_t in_context_sessionlist_next;
                    std::uint64_t in_context_sessionlist_prev;
                    std::uint64_t in_context_shrdmemlist_next;
                    std::uint64_t in_context_shrdmemlist_prev;
                    std::uint64_t in_context_sharebuffer_buffer;
                    std::int64_t in_context_sharebuffer_bufferbarrier;

                    std::uint32_t teecresult;
                    std::int32_t fd;

                    std::uint32_t in_destination_timelow;
                    std::uint32_t in_destination_timemid;
                    std::uint32_t in_destination_timehiandver;

                    std::uint32_t in_connectionmethod;
                    std::uint64_t in_connectiondata;
                    std::uint32_t in_operation_started;
                    std::uint32_t in_operation_paramtypes;
                    std::int32_t in_destination_clockseqandnode_size;
                    std::uint32_t *in_destination_clockseqandnode;

                    std::uint64_t in_operation_param1_tmpref_buffer;
                    std::uint32_t in_operation_param1_tmpref_size;
                    std::uint64_t in_operation_param1_memref_parent;
                    std::uint32_t in_operation_param1_memref_size;
                    std::uint32_t in_operation_param1_memref_offset;
                    std::uint32_t in_operation_param1_value_a;
                    std::uint32_t in_operation_param1_value_b;
                    std::int32_t in_operation_param1_ionref_ionsharefd;
                    std::uint32_t in_operation_param1_ionref_ionsize;

                    std::uint64_t in_operation_param2_tmpref_buffer;
                    std::uint32_t in_operation_param2_tmpref_size;
                    std::uint64_t in_operation_param2_memref_parent;
                    std::uint32_t in_operation_param2_memref_size;
                    std::uint32_t in_operation_param2_memref_offset;
                    std::uint32_t in_operation_param2_value_a;
                    std::uint32_t in_operation_param2_value_b;
                    std::int32_t in_operation_param2_ionref_ionsharefd;
                    std::uint32_t in_operation_param2_ionref_ionsize;

                    std::uint64_t in_operation_param3_tmpref_buffer;
                    std::uint32_t in_operation_param3_tmpref_size;
                    std::uint64_t in_operation_param3_memref_parent;
                    std::uint32_t in_operation_param3_memref_size;
                    std::uint32_t in_operation_param3_memref_offset;
                    std::uint32_t in_operation_param3_value_a;
                    std::uint32_t in_operation_param3_value_b;
                    std::int32_t in_operation_param3_ionref_ionsharefd;
                    std::uint32_t in_operation_param3_ionref_ionsize;

                    std::uint64_t in_operation_param4_tmpref_buffer;
                    std::uint32_t in_operation_param4_tmpref_size;
                    std::uint64_t in_operation_param4_memref_parent;
                    std::uint32_t in_operation_param4_memref_size;
                    std::uint32_t in_operation_param4_memref_offset;
                    std::uint32_t in_operation_param4_value_a;
                    std::uint32_t in_operation_param4_value_b;
                    std::int32_t in_operation_param4_ionref_ionsharefd;
                    std::uint32_t in_operation_param4_ionref_ionsize;

                    std::uint64_t in_operation_session;
                    std::int32_t in_operation_cancelflag;
                    std::uint32_t in_returnorigin;

                    std::uint64_t in_context_addr;

                    unsigned char *ta_path = NULL;
                    std::int32_t ta_path_size = 0;

                    std::uint64_t session_list_next;
                    std::uint64_t session_list_prev;
                    std::uint64_t shrd_mem_list_next;
                    std::uint64_t shrd_mem_list_prev;
                    std::uint64_t share_buffer_buffer;
                    std::int64_t share_buffer_buffer_barrier;

                    std::uint32_t sessionid;
                    std::uint32_t serviceid_timelow;
                    std::uint32_t serviceid_timemid;
                    std::uint32_t serviceid_timehiandver;
                    std::uint32_t *serviceid_clockseqandnode;
                    int serviceid_clockseqandnode_realsize;
                    std::int32_t serviceid_clockseqandnode_outsize;
                    std::uint32_t opscnt;
                    std::uint64_t head_next;
                    std::uint64_t head_prev;
                    std::uint64_t session_context;
                    std::uint32_t started;
                    std::uint32_t paramtypes;
                    std::uint64_t operation_param1_tmpref_buffer;
                    std::uint32_t operation_param1_tmpref_size;
                    std::uint64_t operation_param1_memref_parent;
                    std::uint32_t operation_param1_memref_size;
                    std::uint32_t operation_param1_memref_offset;
                    std::uint32_t operation_param1_value_a;
                    std::uint32_t operation_param1_value_b;
                    std::int32_t operation_param1_ionref_ionsharefd;
                    std::uint32_t operation_param1_ionref_ionsize;
                    std::uint64_t operation_param2_tmpref_buffer;
                    std::uint32_t operation_param2_tmpref_size;
                    std::uint64_t operation_param2_memref_parent;
                    std::uint32_t operation_param2_memref_size;
                    std::uint32_t operation_param2_memref_offset;
                    std::uint32_t operation_param2_value_a;
                    std::uint32_t operation_param2_value_b;
                    std::int32_t operation_param2_ionref_ionsharefd;
                    std::uint32_t operation_param2_ionref_ionsize;
                    std::uint64_t operation_param3_tmpref_buffer;
                    std::uint32_t operation_param3_tmpref_size;
                    std::uint64_t operation_param3_memref_parent;
                    std::uint32_t operation_param3_memref_size;
                    std::uint32_t operation_param3_memref_offset;
                    std::uint32_t operation_param3_value_a;
                    std::uint32_t operation_param3_value_b;
                    std::int32_t operation_param3_ionref_ionsharefd;
                    std::uint32_t operation_param3_ionref_ionsize;
                    std::uint64_t operation_param4_tmpref_buffer;
                    std::uint32_t operation_param4_tmpref_size;
                    std::uint64_t operation_param4_memref_parent;
                    std::uint32_t operation_param4_memref_size;
                    std::uint32_t operation_param4_memref_offset;
                    std::uint32_t operation_param4_value_a;
                    std::uint32_t operation_param4_value_b;
                    std::int32_t operation_param4_ionref_ionsharefd;
                    std::uint32_t operation_param4_ionref_ionsize;
                    std::uint64_t operation_session;
                    std::int32_t operation_cancelflag;
                    std::uint32_t returnorigin;

                    std::uint32_t serial = 0;
                    std::int32_t flag = 0;
                    std::string token;
                    token = opes_request.token();

                    std::string noToken("noToken");

                    int ivaljwtResult = -1;
                    int iforceValidateJwt = global_force_valideta_jwt;

                    if
                          (
                          iforceValidateJwt == 1
                          &&
                          token.compare(noToken) != 0
                          )
                    {
                       char Token[1024];
                       strcpy(Token, (char *) token.data());
                       gettimeofday(&jwt_validate_start, NULL);
                       ivaljwtResult =
                             dbusmethodcall_validate_jwt(
                                   Token
                             );
                       gettimeofday(&jwt_validate_end, NULL);
                       int64_t i64Time_jwt;
                       i64Time_jwt = (jwt_validate_end.tv_sec - jwt_validate_start.tv_sec) * 1000000 +
                                     (jwt_validate_end.tv_usec - jwt_validate_start.tv_usec);
                       printf("gpp opensession validate jwt used time: %ld us. \n", i64Time_jwt);
                       std::cout << "gpp validate opensession jwtsvid" << std::endl;
                    } else
                    {
                       std::cout << "gpp no validate opensession jwtsvid" << std::endl;
                    }

                    if
                          (
                          iforceValidateJwt != 1
                          ||
                          (
                                iforceValidateJwt == 1
                                &&
                                token.compare(noToken) != 0
                                &&
                                ivaljwtResult == NO_ERROR
                          )
                          )
                    {
                       std::cout << "gpp does not need validate opensession jwtsvid or validate jwt succed"
                                 << std::endl;
                       std::cout << "gpp received OpenSession" << std::endl;
                       in_context_fd = opes_request.in_context_fd();
                       in_context_tapath_size = opes_request.in_context_tapath_size();
                       if (in_context_tapath_size > 0)
                       {
                          in_context_tapath = opes_request.in_context_tapath();
                          in_context_tapath_temp = reinterpret_cast<const uint8_t *>(in_context_tapath.c_str());
                          std::cout << "gpp received in_context_tapath_temp: " << in_context_tapath_temp
                                    << std::endl;
                       }
                       std::cout << "gpp received in_context_fd: " << std::dec << in_context_fd
                                 << std::endl;
                       std::cout << "gpp received in_context_tapath_size: " << std::dec
                                 << in_context_tapath_size
                                 << std::endl;
                       in_context_sessionlist_next = opes_request.in_context_sessionlist_next();
                       in_context_sessionlist_prev = opes_request.in_context_sessionlist_prev();
                       in_context_shrdmemlist_next = opes_request.in_context_shrdmemlist_next();
                       in_context_shrdmemlist_prev = opes_request.in_context_shrdmemlist_prev();
                       in_context_sharebuffer_buffer = opes_request.in_context_shrdmemlist_prev();
                       in_context_sharebuffer_bufferbarrier = opes_request.in_context_sharebuffer_bufferbarrier();
                       in_destination_timelow = opes_request.in_destination_timelow();
                       in_destination_timemid = opes_request.in_destination_timemid();

                       in_destination_timehiandver = opes_request.in_destination_timehiandver();
                       in_destination_clockseqandnode_size = opes_request.in_destination_clockseqandnode_size();
                       if (in_destination_clockseqandnode_size > 0)
                       {
                          in_destination_clockseqandnode = new uint32_t[in_destination_clockseqandnode_size];
                          for (int i = 0; i < in_destination_clockseqandnode_size; i++)
                          {
                             in_destination_clockseqandnode[i] = opes_request.in_destination_clockseqandnode(
                                   i);
                          }
                       }

                       in_connectionmethod = opes_request.in_connectionmethod();
                       in_connectiondata = opes_request.in_connectiondata();
                       in_operation_started = opes_request.in_operation_started();
                       in_operation_paramtypes = opes_request.in_operation_paramtypes();
                       in_operation_param1_tmpref_buffer = opes_request.in_operation_param1_tmpref_buffer();
                       in_operation_param1_tmpref_size = opes_request.in_operation_param1_tmpref_size();
                       in_operation_param1_memref_parent = opes_request.in_operation_param1_memref_parent();
                       in_operation_param1_memref_size = opes_request.in_operation_param1_memref_size();
                       in_operation_param1_memref_offset = opes_request.in_operation_param1_memref_offset();
                       in_operation_param1_value_a = opes_request.in_operation_param1_value_a();
                       in_operation_param1_value_b = opes_request.in_operation_param1_value_b();
                       in_operation_param1_ionref_ionsharefd = opes_request.in_operation_param1_ionref_ionsharefd();
                       in_operation_param1_ionref_ionsize = opes_request.in_operation_param1_ionref_ionsize();

                       in_operation_param2_tmpref_buffer = opes_request.in_operation_param2_tmpref_buffer();
                       in_operation_param2_tmpref_size = opes_request.in_operation_param2_tmpref_size();
                       in_operation_param2_memref_parent = opes_request.in_operation_param2_memref_parent();
                       in_operation_param2_memref_size = opes_request.in_operation_param2_memref_size();
                       in_operation_param2_memref_offset = opes_request.in_operation_param2_memref_offset();
                       in_operation_param2_value_a = opes_request.in_operation_param2_value_a();
                       in_operation_param2_value_b = opes_request.in_operation_param2_value_b();
                       in_operation_param2_ionref_ionsharefd = opes_request.in_operation_param2_ionref_ionsharefd();
                       in_operation_param2_ionref_ionsize = opes_request.in_operation_param2_ionref_ionsize();

                       in_operation_param3_tmpref_buffer = opes_request.in_operation_param3_tmpref_buffer();
                       in_operation_param3_tmpref_size = opes_request.in_operation_param3_tmpref_size();
                       in_operation_param3_memref_parent = opes_request.in_operation_param3_memref_parent();
                       in_operation_param3_memref_size = opes_request.in_operation_param3_memref_size();
                       in_operation_param3_memref_offset = opes_request.in_operation_param3_memref_offset();
                       in_operation_param3_value_a = opes_request.in_operation_param3_value_a();
                       in_operation_param3_value_b = opes_request.in_operation_param3_value_b();
                       in_operation_param3_ionref_ionsharefd = opes_request.in_operation_param3_ionref_ionsharefd();
                       in_operation_param3_ionref_ionsize = opes_request.in_operation_param3_ionref_ionsize();

                       in_operation_param4_tmpref_buffer = opes_request.in_operation_param4_tmpref_buffer();
                       in_operation_param4_tmpref_size = opes_request.in_operation_param4_tmpref_size();
                       in_operation_param4_memref_parent = opes_request.in_operation_param4_memref_parent();
                       in_operation_param4_memref_size = opes_request.in_operation_param4_memref_size();
                       in_operation_param4_memref_offset = opes_request.in_operation_param4_memref_offset();
                       in_operation_param4_value_a = opes_request.in_operation_param4_value_a();
                       in_operation_param4_value_b = opes_request.in_operation_param4_value_b();
                       in_operation_param4_ionref_ionsharefd = opes_request.in_operation_param4_ionref_ionsharefd();
                       in_operation_param4_ionref_ionsize = opes_request.in_operation_param4_ionref_ionsize();

                       in_operation_session = opes_request.in_operation_session();
                       in_operation_cancelflag = opes_request.in_operation_cancelflag();
                       in_returnorigin = opes_request.in_returnorigin();
                       in_context_addr = opes_request.in_context_addr();
#if 0
                       printf("   in_session_list_next                  = 0x %16.16lx \n", in_context_sessionlist_next);
                       printf("   in_session_list_prev                  = 0x %16.16lx \n", in_context_sessionlist_prev);
                       printf("   in_shrd_mem_list_next                 = 0x %16.16lx \n", in_context_shrdmemlist_next);
                       printf("   in_shrd_mem_list_prev                 = 0x %16.16lx \n", in_context_shrdmemlist_prev);
                       printf("   in_share_buffer_buffer                = 0x %16.16lx \n", in_context_sharebuffer_buffer);
                       printf("   in_share_buffer_buffer_barrier        = 0x %16.16lx \n", in_context_sharebuffer_bufferbarrier);

                       printf("   in_destination_timelow                = 0x %8.8x \n", in_destination_timelow);
                       printf("   in_destination_timemid                = 0x %8.8x \n", in_destination_timemid);
                       printf("   in_destination_timehiandver           = 0x %8.8x \n", in_destination_timehiandver);
                       if ( in_destination_clockseqandnode_size > 0 )
                       {
                          printf("   in_destination_clockseqandnode        = \n");
                          printf("   ");
                          for (int i = 0; i < in_destination_clockseqandnode_size; i++) {
                             printf(" %8.8x", in_destination_clockseqandnode[i]);
                          }
                          printf("\n");
                       }
                       else
                       {
                          printf("   in_destination_clockseqandnode addr   = 0x %16.16lx \n",
                             (long unsigned int)in_destination_clockseqandnode
                            );
                       }
                       printf("   in_destination_clockseqandnode_size   = 0x %8.8x \n", in_destination_clockseqandnode_size);

                       printf("   in_connectionmethod                   = 0x %8.8x \n", in_connectionmethod);
                       printf("   in_connectiondata                     = 0x %16.16lx \n", in_connectiondata);

                       printf("   in_operation_started                  = 0x %8.8x \n", in_operation_started);
                       printf("   in_operation_paramtypes               = 0x %8.8x \n", in_operation_paramtypes);

                       printf("   in_operation_param1_tmpref_buffer     = 0x %16.16lx \n", in_operation_param1_tmpref_buffer);
                       printf("   in_operation_param1_tmpref_size       = 0x %8.8x \n", in_operation_param1_tmpref_size);
                       printf("   in_operation_param1_memref_parent     = 0x %16.16lx \n", in_operation_param1_memref_parent);
                       printf("   in_operation_param1_memref_size       = 0x %8.8x \n", in_operation_param1_memref_size);
                       printf("   in_operation_param1_memref_offset     = 0x %8.8x \n", in_operation_param1_memref_offset);
                       printf("   in_operation_param1_value_a           = 0x %8.8x \n", in_operation_param1_value_a);
                       printf("   in_operation_param1_value_b           = 0x %8.8x \n", in_operation_param1_value_b);
                       printf("   in_operation_param1_ionref_ionsharefd = 0x %8.8x \n",
                               in_operation_param1_ionref_ionsharefd);
                       printf("   in_operation_param1_ionref_ionsize    = 0x %8.8x \n", in_operation_param1_ionref_ionsize);

                       printf("   in_operation_param2_tmpref_buffer     = 0x %16.16lx \n", in_operation_param2_tmpref_buffer);
                       printf("   in_operation_param2_tmpref_size       = 0x %8.8x \n", in_operation_param2_tmpref_size);
                       printf("   in_operation_param2_memref_parent     = 0x %16.16lx \n", in_operation_param2_memref_parent);
                       printf("   in_operation_param2_memref_size       = 0x %8.8x \n", in_operation_param2_memref_size);
                       printf("   in_operation_param2_memref_offset     = 0x %8.8x \n", in_operation_param2_memref_offset);
                       printf("   in_operation_param2_value_a           = 0x %8.8x \n", in_operation_param3_value_a);
                       printf("   in_operation_param2_value_b           = 0x %8.8x \n", in_operation_param3_value_b);
                       printf("   in_operation_param2_ionref_ionsharefd = 0x %8.8x \n", in_operation_param3_ionref_ionsharefd);
                       printf("   in_operation_param2_ionref_ionsize    = 0x %8.8x \n", in_operation_param3_ionref_ionsize);

                       printf("   in_operation_param3_tmpref_buffer     = 0x %16.16lx \n", in_operation_param3_tmpref_buffer);
                       printf("   in_operation_param3_tmpref_size       = 0x %8.8x \n", in_operation_param3_tmpref_size);
                       printf("   in_operation_param3_memref_parent     = 0x %16.16lx \n", in_operation_param3_memref_parent);
                       printf("   in_operation_param3_memref_size       = 0x %8.8x \n", in_operation_param3_memref_size);
                       printf("   in_operation_param3_memref_offset     = 0x %8.8x \n", in_operation_param3_memref_offset);
                       printf("   in_operation_param3_value_a           = 0x %8.8x \n", in_operation_param3_value_a);
                       printf("   in_operation_param3_value_b           = 0x %8.8x \n", in_operation_param3_value_b);
                       printf("   in_operation_param3_ionref_ionsharefd = 0x %8.8x \n", in_operation_param3_ionref_ionsharefd);
                       printf("   in_operation_param3_ionref_ionsize    = 0x %8.8x \n", in_operation_param3_ionref_ionsize);

                       printf("   in_operation_param4_tmpref_buffer     = 0x %16.16lx \n", in_operation_param4_tmpref_buffer);
                       printf("   in_operation_param4_tmpref_size       = 0x %8.8x \n", in_operation_param4_tmpref_size);
                       printf("   in_operation_param4_memref_parent     = 0x %16.16lx \n", in_operation_param4_memref_parent);
                       printf("   in_operation_param4_memref_size       = 0x %8.8x \n", in_operation_param4_memref_size);
                       printf("   in_operation_param4_memref_offset     = 0x %8.8x \n", in_operation_param4_memref_offset);
                       printf("   in_operation_param4_value_a           = 0x %8.8x \n", in_operation_param4_value_a);
                       printf("   in_operation_param4_value_b           = 0x %8.8x \n", in_operation_param4_value_b);
                       printf("   in_operation_param4_ionref_ionsharefd = 0x %8.8x \n", in_operation_param4_ionref_ionsharefd);
                       printf("   in_operation_param4_ionref_ionsize    = 0x %8.8x \n", in_operation_param4_ionref_ionsize);

                       printf("   in_operation_session                  = 0x %16.16lx \n", in_operation_session);
                       printf("   in_operation_cancelflag               = 0x %8.8x \n", in_operation_cancelflag);

                       printf("   in_returnorigin                       = 0x %8.8x \n", in_returnorigin);
#endif
                       std::cout << "gpp received in_context_addr: 0x " << std::hex << std::setfill('0')
                                 << std::setw(16) << in_context_addr << std::endl;
                       ta_path = (unsigned char *) malloc(1024 * sizeof(char));
                       ta_path_size = 1024;
                       memset((char *) ta_path, 0, 1024);

                       uint32_t context_tapath_outsize;
                       uint32_t serviceid_clockseqandnode_outsize_temp;
                       uint32_t returnorigin_temp;

                       serviceid_clockseqandnode_realsize = 8;
                       serviceid_clockseqandnode =
                             (std::uint32_t *) malloc(
                                   serviceid_clockseqandnode_realsize * sizeof(std::uint32_t)
                             );

                       char workername[1024];
                       memset((char *) workername, 0, 1024);
                       int ifound = 0;
                       int iworker;

                       pthread_mutex_lock(mutex_workerrec_);
                       for (iworker = 0; iworker < global_max_num_worker; iworker++)
                       {
                          if (workerrec_[iworker].context_fd == in_context_fd &&
                              workerrec_[iworker].context_addr == in_context_addr
                                )
                          {
                             sprintf(workername, "%s%d", "gpworker", iworker);
                             std::cout << "gpp method call worker No: " << std::dec << iworker << std::endl;
                             ifound = 1;
                             break;
                          }
                       }
                       pthread_mutex_unlock(mutex_workerrec_);
                       if (ifound == 0)
                       {
                          printf("gpp can't find the woker for the context. \n");

                          teecresult = 0xAAAA0017;

                          fd = 0x0;
                          ta_path = NULL;
                          charp = ta_path;
                          session_list_next = 0x0;
                          session_list_prev = 0x0;
                          shrd_mem_list_next = 0x0;
                          shrd_mem_list_prev = 0x0;
                          share_buffer_buffer = 0;
                          share_buffer_buffer_barrier = 0x0;

                          sessionid = 0x0;
                          serviceid_timelow = 0x0;
                          serviceid_timemid = 0x0;
                          serviceid_timehiandver = 0x0;
                          serviceid_clockseqandnode_realsize = 8;
                          serviceid_clockseqandnode =
                                (uint32_t *) malloc(
                                      serviceid_clockseqandnode_realsize * sizeof(uint32_t)
                                );
                          for (int i = 0; i < serviceid_clockseqandnode_realsize; i++)
                          {
                             serviceid_clockseqandnode[i] = 0x0;
                          }
                          serviceid_clockseqandnode_outsize = 8;
                          opscnt = 0x0;
                          head_next = 0x0;
                          head_prev = 0x0;
                          session_context = 0x0;

                          started = 0x0;
                          paramtypes = 0x0;

                          operation_param1_tmpref_buffer = 0x0;
                          operation_param1_tmpref_size = 0x0;
                          operation_param1_memref_parent = 0x0;
                          operation_param1_memref_size = 0x0;
                          operation_param1_memref_offset = 0x0;
                          operation_param1_value_a = 0x0;
                          operation_param1_value_b = 0x0;
                          operation_param1_ionref_ionsharefd = 0x0;
                          operation_param1_ionref_ionsize = 0x0;

                          operation_param2_tmpref_buffer = 0x0;
                          operation_param2_tmpref_size = 0x0;
                          operation_param2_memref_parent = 0x0;
                          operation_param2_memref_size = 0x0;
                          operation_param2_memref_offset = 0x0;
                          operation_param2_value_a = 0x0;
                          operation_param2_value_b = 0x0;
                          operation_param2_ionref_ionsharefd = 0x0;
                          operation_param2_ionref_ionsize = 0x0;

                          operation_param3_tmpref_buffer = 0x0;
                          operation_param3_tmpref_size = 0x0;
                          operation_param3_memref_parent = 0x0;
                          operation_param3_memref_size = 0x0;
                          operation_param3_memref_offset = 0x0;
                          operation_param3_value_a = 0x0;
                          operation_param3_value_b = 0x0;
                          operation_param3_ionref_ionsharefd = 0x0;
                          operation_param3_ionref_ionsize = 0x0;

                          operation_param4_tmpref_buffer = 0x0;
                          operation_param4_tmpref_size = 0x0;
                          operation_param4_memref_parent = 0x0;
                          operation_param4_memref_size = 0x0;
                          operation_param4_memref_offset = 0x0;
                          operation_param4_value_a = 0x0;
                          operation_param4_value_b = 0x0;
                          operation_param4_ionref_ionsharefd = 0x0;
                          operation_param4_ionref_ionsize = 0x0;

                          operation_session = 0x0;
                          operation_cancelflag = 0x0;

                          returnorigin = 0x0;

                          opes_reply.set_teecresult(teecresult);
                          opes_reply.set_context_fd(fd);
                          opes_reply.set_context_tapath_outsize(ta_path_size);
                          opes_reply.set_context_sessionlist_next(session_list_next);
                          opes_reply.set_context_sessionlist_prev(session_list_prev);
                          opes_reply.set_context_shrdmemlist_prev(shrd_mem_list_prev);
                          opes_reply.set_context_shrdmemlist_next(shrd_mem_list_next);
                          opes_reply.set_context_sharebuffer_buffer(share_buffer_buffer);
                          opes_reply.set_context_sharebuffer_bufferbarrier(share_buffer_buffer_barrier);
                          opes_reply.set_session_sessionid(sessionid);
                          opes_reply.set_session_serviceid_timelow(serviceid_timelow);
                          opes_reply.set_session_serviceid_timemid(serviceid_timemid);
                          opes_reply.set_session_serviceid_timehiandver(serviceid_timehiandver);
                          opes_reply.set_session_serviceid_clockseqandnode_outsize(
                                serviceid_clockseqandnode_outsize);
                          if (serviceid_clockseqandnode_outsize > 0 &&
                              serviceid_clockseqandnode != NULL
                                )
                          {
                             for (int i = 0; i < serviceid_clockseqandnode_outsize; i++)
                                opes_reply.add_session_serviceid_clockseqandnode(
                                      serviceid_clockseqandnode[i]);
                          }
                          opes_reply.set_session_opscnt(opscnt);
                          opes_reply.set_session_head_next(head_next);
                          opes_reply.set_session_head_prev(head_prev);
                          opes_reply.set_session_context(session_context);
                          opes_reply.set_operation_started(started);
                          opes_reply.set_operation_paramtypes(paramtypes);
                          opes_reply.set_operation_param1_tmpref_buffer(operation_param1_tmpref_buffer);
                          opes_reply.set_operation_param1_tmpref_size(operation_param1_tmpref_size);
                          opes_reply.set_operation_param1_memref_parent(operation_param1_memref_parent);
                          opes_reply.set_operation_param1_memref_size(operation_param1_memref_size);
                          opes_reply.set_operation_param1_memref_offset(operation_param1_memref_offset);
                          opes_reply.set_operation_param1_value_a(operation_param1_value_a);
                          opes_reply.set_operation_param1_value_b(operation_param1_value_b);
                          opes_reply.set_operation_param1_ionref_ionsharefd(
                                operation_param1_ionref_ionsharefd);
                          opes_reply.set_operation_param1_ionref_ionsize(operation_param1_ionref_ionsize);

                          opes_reply.set_operation_param2_tmpref_buffer(operation_param2_tmpref_buffer);
                          opes_reply.set_operation_param2_tmpref_size(operation_param2_tmpref_size);
                          opes_reply.set_operation_param2_memref_parent(operation_param2_memref_parent);
                          opes_reply.set_operation_param2_memref_size(operation_param2_memref_size);
                          opes_reply.set_operation_param2_memref_offset(operation_param2_memref_offset);
                          opes_reply.set_operation_param2_value_a(operation_param2_value_a);
                          opes_reply.set_operation_param2_value_b(operation_param2_value_b);
                          opes_reply.set_operation_param2_ionref_ionsharefd(
                                operation_param2_ionref_ionsharefd);
                          opes_reply.set_operation_param2_ionref_ionsize(operation_param2_ionref_ionsize);

                          opes_reply.set_operation_param3_tmpref_buffer(operation_param3_tmpref_buffer);
                          opes_reply.set_operation_param3_tmpref_size(operation_param3_tmpref_size);
                          opes_reply.set_operation_param3_memref_parent(operation_param3_memref_parent);
                          opes_reply.set_operation_param3_memref_size(operation_param3_memref_size);
                          opes_reply.set_operation_param3_memref_offset(operation_param3_memref_offset);
                          opes_reply.set_operation_param3_value_a(operation_param3_value_a);
                          opes_reply.set_operation_param3_value_b(operation_param3_value_b);
                          opes_reply.set_operation_param3_ionref_ionsharefd(
                                operation_param3_ionref_ionsharefd);
                          opes_reply.set_operation_param3_ionref_ionsize(operation_param3_ionref_ionsize);

                          opes_reply.set_operation_param4_tmpref_buffer(operation_param4_tmpref_buffer);
                          opes_reply.set_operation_param4_tmpref_size(operation_param4_tmpref_size);
                          opes_reply.set_operation_param4_memref_parent(operation_param4_memref_parent);
                          opes_reply.set_operation_param4_memref_size(operation_param4_memref_size);
                          opes_reply.set_operation_param4_memref_offset(operation_param4_memref_offset);
                          opes_reply.set_operation_param4_value_a(operation_param4_value_a);
                          opes_reply.set_operation_param4_value_b(operation_param4_value_b);
                          opes_reply.set_operation_param4_ionref_ionsharefd(
                                operation_param4_ionref_ionsharefd);
                          opes_reply.set_operation_param4_ionref_ionsize(operation_param4_ionref_ionsize);

                          opes_reply.set_operation_session(operation_session);
                          opes_reply.set_operation_cancelflag(operation_cancelflag);
                          opes_reply.set_returnorigin(returnorigin);

                          status_ = FINISH;

                          opes_response.Finish(opes_reply, Status::OK, this);
                       } else
                       {
                          method_call_teec_opensession(
                                workername,

                                in_context_fd,
                                in_context_tapath_temp,
                                in_context_tapath_size,
                                in_context_sessionlist_next,
                                in_context_sessionlist_prev,
                                in_context_shrdmemlist_next,
                                in_context_shrdmemlist_prev,
                                in_context_sharebuffer_buffer,
                                in_context_sharebuffer_bufferbarrier,

                                in_destination_timelow,
                                in_destination_timemid,
                                in_destination_timehiandver,
                                in_destination_clockseqandnode,
                                in_destination_clockseqandnode_size,

                                in_connectionmethod,
                                in_connectiondata,

                                in_operation_started,
                                in_operation_paramtypes,

                                in_operation_param1_tmpref_buffer,
                                in_operation_param1_tmpref_size,
                                in_operation_param1_memref_parent,
                                in_operation_param1_memref_size,
                                in_operation_param1_memref_offset,
                                in_operation_param1_value_a,
                                in_operation_param1_value_b,
                                in_operation_param1_ionref_ionsharefd,
                                in_operation_param1_ionref_ionsize,

                                in_operation_param2_tmpref_buffer,
                                in_operation_param2_tmpref_size,
                                in_operation_param2_memref_parent,
                                in_operation_param2_memref_size,
                                in_operation_param2_memref_offset,
                                in_operation_param2_value_a,
                                in_operation_param2_value_b,
                                in_operation_param2_ionref_ionsharefd,
                                in_operation_param2_ionref_ionsize,

                                in_operation_param3_tmpref_buffer,
                                in_operation_param3_tmpref_size,
                                in_operation_param3_memref_parent,
                                in_operation_param3_memref_size,
                                in_operation_param3_memref_offset,
                                in_operation_param3_value_a,
                                in_operation_param3_value_b,
                                in_operation_param3_ionref_ionsharefd,
                                in_operation_param3_ionref_ionsize,

                                in_operation_param4_tmpref_buffer,
                                in_operation_param4_tmpref_size,
                                in_operation_param4_memref_parent,
                                in_operation_param4_memref_size,
                                in_operation_param4_memref_offset,
                                in_operation_param4_value_a,
                                in_operation_param4_value_b,
                                in_operation_param4_ionref_ionsharefd,
                                in_operation_param4_ionref_ionsize,

                                in_operation_session,
                                in_operation_cancelflag,

                                in_returnorigin,

                                in_context_addr,


                                &teecresult,

                                &fd,
                                ta_path,
                                ta_path_size,
                                &context_tapath_outsize,
                                &session_list_next,
                                &session_list_prev,
                                &shrd_mem_list_next,
                                &shrd_mem_list_prev,
                                &share_buffer_buffer,
                                &share_buffer_buffer_barrier,

                                &sessionid,
                                &serviceid_timelow,
                                &serviceid_timemid,
                                &serviceid_timehiandver,
                                serviceid_clockseqandnode,
                                serviceid_clockseqandnode_realsize,
                                &serviceid_clockseqandnode_outsize_temp,
                                &opscnt,
                                &head_next,
                                &head_prev,
                                &session_context,

                                &started,
                                &paramtypes,

                                &operation_param1_tmpref_buffer,
                                &operation_param1_tmpref_size,
                                &operation_param1_memref_parent,
                                &operation_param1_memref_size,
                                &operation_param1_memref_offset,
                                &operation_param1_value_a,
                                &operation_param1_value_b,
                                &operation_param1_ionref_ionsharefd,
                                &operation_param1_ionref_ionsize,

                                &operation_param2_tmpref_buffer,
                                &operation_param2_tmpref_size,
                                &operation_param2_memref_parent,
                                &operation_param2_memref_size,
                                &operation_param2_memref_offset,
                                &operation_param2_value_a,
                                &operation_param2_value_b,
                                &operation_param2_ionref_ionsharefd,
                                &operation_param2_ionref_ionsize,

                                &operation_param3_tmpref_buffer,
                                &operation_param3_tmpref_size,
                                &operation_param3_memref_parent,
                                &operation_param3_memref_size,
                                &operation_param3_memref_offset,
                                &operation_param3_value_a,
                                &operation_param3_value_b,
                                &operation_param3_ionref_ionsharefd,
                                &operation_param3_ionref_ionsize,

                                &operation_param4_tmpref_buffer,
                                &operation_param4_tmpref_size,
                                &operation_param4_memref_parent,
                                &operation_param4_memref_size,
                                &operation_param4_memref_offset,
                                &operation_param4_value_a,
                                &operation_param4_value_b,
                                &operation_param4_ionref_ionsharefd,
                                &operation_param4_ionref_ionsize,

                                &operation_session,
                                &operation_cancelflag,

                                &returnorigin_temp
                          );
                          if (teecresult == 0)
                          {
                             pthread_mutex_lock(mutex_workerrec_);
                             sin_t *sinIns = (sin_t *) malloc(sizeof(sin_t));
                             sinIns->session_id = sessionid;
                             struct timeval tvcreate;
                             gettimeofday(&tvcreate, NULL);
                             sinIns->session_createtime = tvcreate;
                             workerrec_[iworker].context_createtime = tvcreate;
                             if (workerrec_[iworker].first == NULL)
                             {
                                sinIns->next = NULL;
                                sinIns->prev = NULL;
                                workerrec_[iworker].first = sinIns;
                                workerrec_[iworker].last = sinIns;
                                workerrec_[iworker].sessionid_count = 1;
                             } else
                             {
                                sinIns->prev = workerrec_[iworker].last;
                                sinIns->next = NULL;
                                workerrec_[iworker].last->next = sinIns;
                                workerrec_[iworker].last = sinIns;
                                workerrec_[iworker].sessionid_count =
                                      workerrec_[iworker].sessionid_count + 1;
                             }
                             pthread_mutex_unlock(mutex_workerrec_);
                          }
                          serviceid_clockseqandnode_outsize =
                                serviceid_clockseqandnode_outsize_temp;
                          returnorigin = returnorigin_temp;

                          if (ta_path_size >= context_tapath_outsize)
                          {
                             ta_path_size = context_tapath_outsize;
                             charp = ta_path;
                          } else
                          {
                             ta_path_size = 0;
                             charp = NULL;
                          }

                          if (
                                serviceid_clockseqandnode_realsize >= serviceid_clockseqandnode_outsize &&
                                8 >= serviceid_clockseqandnode_outsize
                                )
                          {
                             serviceid_clockseqandnode_realsize = serviceid_clockseqandnode_outsize;
                          } else
                          {
                             serviceid_clockseqandnode_realsize = 0;
                             serviceid_clockseqandnode_outsize = 0;
                          }
                          opes_reply.set_teecresult(teecresult);
                          opes_reply.set_context_fd(fd);
                          opes_reply.set_context_tapath_outsize(ta_path_size);

                          if (ta_path_size > 0 &&
                              charp != NULL &&
                              strlen((const char *) charp) > 0
                                )
                          {
                             charpp = (const char *) charp;
                             if (utf8_check_is_valid(charpp))
                             {
                                ta_path_size = strlen((const char *) charp);
                             } else
                             {
                                ta_path_size = 0;
                             }
                          } else
                          {
                             ta_path_size = 0;
                          }
                          if (ta_path_size > 0)
                          {
                             opes_reply.set_context_tapath(charpp);
                          }

                          opes_reply.set_context_sessionlist_next(session_list_next);
                          opes_reply.set_context_sessionlist_prev(session_list_prev);
                          opes_reply.set_context_shrdmemlist_prev(shrd_mem_list_prev);
                          opes_reply.set_context_shrdmemlist_next(shrd_mem_list_next);
                          opes_reply.set_context_sharebuffer_buffer(share_buffer_buffer);
                          opes_reply.set_context_sharebuffer_bufferbarrier(share_buffer_buffer_barrier);
                          opes_reply.set_session_sessionid(sessionid);
                          opes_reply.set_session_serviceid_timelow(serviceid_timelow);
                          opes_reply.set_session_serviceid_timemid(serviceid_timemid);
                          opes_reply.set_session_serviceid_timehiandver(serviceid_timehiandver);
                          opes_reply.set_session_serviceid_clockseqandnode_outsize(
                                serviceid_clockseqandnode_outsize);
                          if (serviceid_clockseqandnode_outsize > 0 &&
                              serviceid_clockseqandnode != NULL
                                )
                          {
                             for (int i = 0; i < serviceid_clockseqandnode_outsize; i++)
                                opes_reply.add_session_serviceid_clockseqandnode(
                                      serviceid_clockseqandnode[i]);
                          }
                          opes_reply.set_session_opscnt(opscnt);
                          opes_reply.set_session_head_next(head_next);
                          opes_reply.set_session_head_prev(head_prev);
                          opes_reply.set_session_context(session_context);
                          opes_reply.set_operation_started(started);
                          opes_reply.set_operation_paramtypes(paramtypes);
                          opes_reply.set_operation_param1_tmpref_buffer(operation_param1_tmpref_buffer);
                          opes_reply.set_operation_param1_tmpref_size(operation_param1_tmpref_size);
                          opes_reply.set_operation_param1_memref_parent(operation_param1_memref_parent);
                          opes_reply.set_operation_param1_memref_size(operation_param1_memref_size);
                          opes_reply.set_operation_param1_memref_offset(operation_param1_memref_offset);
                          opes_reply.set_operation_param1_value_a(operation_param1_value_a);
                          opes_reply.set_operation_param1_value_b(operation_param1_value_b);
                          opes_reply.set_operation_param1_ionref_ionsharefd(
                                operation_param1_ionref_ionsharefd);
                          opes_reply.set_operation_param1_ionref_ionsize(operation_param1_ionref_ionsize);

                          opes_reply.set_operation_param2_tmpref_buffer(operation_param2_tmpref_buffer);
                          opes_reply.set_operation_param2_tmpref_size(operation_param2_tmpref_size);
                          opes_reply.set_operation_param2_memref_parent(operation_param2_memref_parent);
                          opes_reply.set_operation_param2_memref_size(operation_param2_memref_size);
                          opes_reply.set_operation_param2_memref_offset(operation_param2_memref_offset);
                          opes_reply.set_operation_param2_value_a(operation_param2_value_a);
                          opes_reply.set_operation_param2_value_b(operation_param2_value_b);
                          opes_reply.set_operation_param2_ionref_ionsharefd(
                                operation_param2_ionref_ionsharefd);
                          opes_reply.set_operation_param2_ionref_ionsize(operation_param2_ionref_ionsize);

                          opes_reply.set_operation_param3_tmpref_buffer(operation_param3_tmpref_buffer);
                          opes_reply.set_operation_param3_tmpref_size(operation_param3_tmpref_size);
                          opes_reply.set_operation_param3_memref_parent(operation_param3_memref_parent);
                          opes_reply.set_operation_param3_memref_size(operation_param3_memref_size);
                          opes_reply.set_operation_param3_memref_offset(operation_param3_memref_offset);
                          opes_reply.set_operation_param3_value_a(operation_param3_value_a);
                          opes_reply.set_operation_param3_value_b(operation_param3_value_b);
                          opes_reply.set_operation_param3_ionref_ionsharefd(
                                operation_param3_ionref_ionsharefd);
                          opes_reply.set_operation_param3_ionref_ionsize(operation_param3_ionref_ionsize);

                          opes_reply.set_operation_param4_tmpref_buffer(operation_param4_tmpref_buffer);
                          opes_reply.set_operation_param4_tmpref_size(operation_param4_tmpref_size);
                          opes_reply.set_operation_param4_memref_parent(operation_param4_memref_parent);
                          opes_reply.set_operation_param4_memref_size(operation_param4_memref_size);
                          opes_reply.set_operation_param4_memref_offset(operation_param4_memref_offset);
                          opes_reply.set_operation_param4_value_a(operation_param4_value_a);
                          opes_reply.set_operation_param4_value_b(operation_param4_value_b);
                          opes_reply.set_operation_param4_ionref_ionsharefd(
                                operation_param4_ionref_ionsharefd);
                          opes_reply.set_operation_param4_ionref_ionsize(operation_param4_ionref_ionsize);

                          opes_reply.set_operation_session(operation_session);
                          opes_reply.set_operation_cancelflag(operation_cancelflag);
                          opes_reply.set_returnorigin(returnorigin);

                          status_ = FINISH;
                          gettimeofday(&end, NULL);
                          int64_t i64Time;
                          i64Time = (end.tv_sec - start.tv_sec) * 1000000 +
                                    (end.tv_usec - start.tv_usec);
                          printf("gpp opensession used time: %ld us. \n", i64Time);

                          //status_ = FINISH;
                          opes_response.Finish(opes_reply, Status::OK, this);
                       }
                    }else
                    {
                       std::cout << "gpp receive no opensession jwtsvid or validate jwt failed" << std::endl;
                       flag = 2;
                       opes_reply.set_flag(flag);
                       status_ = FINISH;
                       opes_response.Finish(opes_reply, Status::OK, this);
                    }
                    break;
                 }

                 case ServerImpl::CallData::SS_TEECC_CloseSession:
                 {
                    struct timeval start, end, jwt_validate_start, jwt_validate_end;
                    gettimeofday(&start, NULL);

                    std::uint32_t in_session_sessionid;
                    std::uint32_t in_session_serviceid_timelow;
                    std::uint32_t in_session_serviceid_timemid;
                    std::uint32_t in_session_serviceid_timehiandver;
                    std::uint32_t in_session_serviceid_clockseqandnode_size;
                    std::uint32_t *in_session_serviceid_clockseqandnode;
                    std::uint32_t in_session_opscnt;
                    std::uint64_t in_session_head_next;
                    std::uint64_t in_session_head_prev;
                    std::uint64_t in_session_context;

                    std::uint32_t sessionid;
                    std::uint32_t serviceid_timelow;
                    std::uint32_t serviceid_timemid;
                    std::uint32_t serviceid_timehiandver;
                    std::uint32_t *serviceid_clockseqandnode;
                    std::uint32_t serviceid_clockseqandnode_outsize;
                    int serviceid_clockseqandnode_realsize;
                    std::uint32_t opscnt;
                    std::uint64_t head_next;
                    std::uint64_t head_prev;
                    std::uint64_t session_context;

                    std::uint32_t serial = 0;
                    std::int32_t flag = 0;

                    std::string token;
                    token = close_request.token();

                    std::string noToken("noToken");
                    int ivaljwtResult = -1;
                    int iforceValidateJwt = global_force_valideta_jwt;

                    if
                          (
                          iforceValidateJwt == 1
                          &&
                          token.compare(noToken) != 0
                          )
                    {
                       char Token[1024];
                       strcpy(Token, (char *) token.data());
                       gettimeofday(&jwt_validate_start, NULL);
                       ivaljwtResult =
                             dbusmethodcall_validate_jwt(
                                   Token
                             );
                       gettimeofday(&jwt_validate_end, NULL);
                       int64_t i64Time_jwt;
                       i64Time_jwt = (jwt_validate_end.tv_sec - jwt_validate_start.tv_sec) * 1000000 +
                                     (jwt_validate_end.tv_usec - jwt_validate_start.tv_usec);
                       printf("gpp closesession validate jwt used time: %ld us. \n", i64Time_jwt);
                       std::cout << "gpp validate closesession jwtsvid" << std::endl;
                    } else
                    {
                       std::cout << "gpp no validate closesession jwtsvid" << std::endl;
                    }

                    if
                          (
                          iforceValidateJwt != 1
                          ||
                          (
                                iforceValidateJwt == 1
                                &&
                                token.compare(noToken) != 0
                                &&
                                ivaljwtResult == NO_ERROR
                          )
                          )
                    {
                       std::cout << "gpp does not need validate closesession jwtsvid or validate jwt succed"
                                 << std::endl;
                       std::cout << "gpp received CloseSesssion " << std::endl;
                       in_session_sessionid = close_request.in_session_sessionid();
                       in_session_serviceid_timelow = close_request.in_session_serviceid_timelow();
                       in_session_serviceid_timemid = close_request.in_session_serviceid_timemid();
                       in_session_serviceid_timehiandver = close_request.in_session_serviceid_timehiandver();
                       in_session_serviceid_clockseqandnode_size = close_request.in_session_serviceid_clockseqandnode_size();
                       if (in_session_serviceid_clockseqandnode_size > 0)
                       {
                          in_session_serviceid_clockseqandnode = new uint32_t[in_session_serviceid_clockseqandnode_size];
                          for (int i = 0; i < in_session_serviceid_clockseqandnode_size; i++)
                          {
                             in_session_serviceid_clockseqandnode[i] = close_request.in_session_serviceid_clockseqandnode(
                                   i);
                          }
                       }
                       in_session_opscnt = close_request.in_session_opscnt();
                       in_session_head_next = close_request.in_session_head_next();
                       in_session_head_prev = close_request.in_session_head_prev();
                       in_session_context = close_request.in_session_context();
#if 0
                       printf("   in_session_serviceid_timelow                = 0x %8.8x \n", in_session_serviceid_timelow);
                       printf("   in_session_serviceid_timemid                = 0x %8.8x \n", in_session_serviceid_timemid);
                       printf("   in_session_serviceid_timehiandver           = 0x %8.8x \n",
                              in_session_serviceid_timehiandver);
                       printf("   in_session_serviceid_clockseqandnode        = \n");
                       printf("   ");
                       for (int i = 0; i < in_session_serviceid_clockseqandnode_size; i++) {
                           printf(" %8.8x", in_session_serviceid_clockseqandnode[i]);
                       }
                       printf("\n");
                       printf("   in_session_serviceid_clockseqandnode_size   = 0x %8.8x \n",
                         in_session_serviceid_clockseqandnode_size);
                       printf("   in_session_opscnt                           = 0x %8.8x \n", in_session_opscnt);
                       printf("   in_session_head_next                        = 0x %16.16lx \n", in_session_head_next);
                       printf("   in_session_head_prev                        = 0x %16.16lx \n", in_session_head_prev);
#endif
                       std::cout << "gpp received in_session_sessionid: 0x " << std::hex << std::setfill('0')
                                 << std::setw(8) << in_session_sessionid << std::endl;
                       std::cout << "gpp received in_session_context: 0x " << std::hex << std::setfill('0')
                                 << std::setw(16) << in_session_context << std::endl;

                       uint32_t serviceid_clockseqandnode_outsize_temp;
                       serviceid_clockseqandnode_realsize = 8;
                       serviceid_clockseqandnode =
                             (std::uint32_t *) malloc(
                                   serviceid_clockseqandnode_realsize * sizeof(std::uint32_t)
                             );
                       char workername[1024];
                       memset((char *) workername, 0, 1024);
                       int ifound = 0;
                       int iworker;
                       sin_t *sinIns;

                       pthread_mutex_lock(mutex_workerrec_);
                       for (iworker = 0; iworker < global_max_num_worker; iworker++)
                       {
                          if (workerrec_[iworker].context_addr == in_session_context)
                          {
                             sinIns = NULL;
                             if (workerrec_[iworker].first != NULL)
                             {
                                sinIns = workerrec_[iworker].first;
                                do
                                {
                                   if (sinIns->session_id == in_session_sessionid)
                                   {
                                      sprintf(workername, "%s%d", "gpworker", iworker);
                                      std::cout << "gpp method call worker No: " << std::dec << iworker << std::endl;
                                      ifound = 1;
                                      break;
                                   }
                                   sinIns = sinIns->next;
                                } while (sinIns != NULL);

                                if (ifound == 1)
                                {
                                   break;
                                }
                             }
                          }
                       }
                       pthread_mutex_unlock(mutex_workerrec_);
                       if (ifound == 0)
                       {
                          printf("gpp can't find the worker for the session and the context. \n");

                          sessionid = 0x0;
                          serviceid_timelow = 0x0;
                          serviceid_timemid = 0x0;
                          serviceid_timehiandver = 0x0;
                          opscnt = 0x0;
                          head_next = 0x0;
                          head_prev = 0x0;
                          session_context = 0x0;

                          serviceid_clockseqandnode_realsize = 8;
                          serviceid_clockseqandnode =
                                (uint32_t *) malloc(
                                      serviceid_clockseqandnode_realsize * sizeof(uint32_t)
                                );
                          for (int i = 0; i < serviceid_clockseqandnode_realsize; i++)
                          {
                             serviceid_clockseqandnode[i] = 0x0;
                          }
                          serviceid_clockseqandnode_outsize = 8;
                          close_reply.set_session_sessionid(sessionid);
                          close_reply.set_session_serviceid_timelow(serviceid_timelow);
                          close_reply.set_session_serviceid_timemid(serviceid_timemid);
                          close_reply.set_session_serviceid_timehiandver(serviceid_timehiandver);
                          close_reply.set_session_serviceid_cad_outsize(serviceid_clockseqandnode_outsize);
                          if (serviceid_clockseqandnode_outsize > 0 &&
                              serviceid_clockseqandnode != NULL
                                )
                          {
                             for (int i = 0; i < serviceid_clockseqandnode_outsize; i++)
                                close_reply.add_session_serviceid_clockseqandnode(serviceid_clockseqandnode[i]);
                          }
                          close_reply.set_session_opscnt(opscnt);
                          close_reply.set_session_head_next(head_next);
                          close_reply.set_session_head_prev(head_prev);
                          close_reply.set_session_context(session_context);

                          status_ = FINISH;

                          close_response.Finish(close_reply, Status::OK, this);
                       } else
                       {
                          method_call_teec_closesession(
                                workername,

                                in_session_sessionid,
                                in_session_serviceid_timelow,
                                in_session_serviceid_timemid,
                                in_session_serviceid_timehiandver,
                                in_session_serviceid_clockseqandnode,
                                in_session_serviceid_clockseqandnode_size,
                                in_session_opscnt,
                                in_session_head_next,
                                in_session_head_prev,
                                in_session_context,

                                &sessionid,
                                &serviceid_timelow,
                                &serviceid_timemid,
                                &serviceid_timehiandver,
                                serviceid_clockseqandnode,
                                serviceid_clockseqandnode_realsize,
                                &serviceid_clockseqandnode_outsize_temp,
                                &opscnt,
                                &head_next,
                                &head_prev,
                                &session_context
                          );
                          pthread_mutex_lock(mutex_workerrec_);
                          sin_t *sinTemp;
                          sinTemp = sinIns->prev;
                          struct timeval tvcreate;
                          gettimeofday(&tvcreate, NULL);
                          workerrec_[iworker].context_createtime = tvcreate;
                          if (sinTemp != NULL)
                          {
                             sinTemp->next = sinIns->next;
                          }
                          sinTemp = sinIns->next;
                          if (sinTemp != NULL)
                          {
                             sinTemp->prev = sinIns->prev;
                          }
                          if (workerrec_[iworker].last == sinIns)
                          {
                             workerrec_[iworker].last = sinIns->prev;
                          }
                          if (workerrec_[iworker].first == sinIns)
                          {
                             workerrec_[iworker].first = sinIns->next;
                          }
                          free(sinIns);
                          workerrec_[iworker].sessionid_count =
                                workerrec_[iworker].sessionid_count - 1;
                          pthread_mutex_unlock(mutex_workerrec_);

                          serviceid_clockseqandnode_outsize = serviceid_clockseqandnode_outsize_temp;

                          if (
                                serviceid_clockseqandnode_realsize >= serviceid_clockseqandnode_outsize &&
                                8 >= serviceid_clockseqandnode_outsize
                                )
                          {
                             serviceid_clockseqandnode_realsize = serviceid_clockseqandnode_outsize;
                          } else
                          {
                             serviceid_clockseqandnode_realsize = 0;
                             serviceid_clockseqandnode_outsize = 0;
                          }
                          close_reply.set_session_sessionid(sessionid);
                          close_reply.set_session_serviceid_timelow(serviceid_timelow);
                          close_reply.set_session_serviceid_timemid(serviceid_timemid);
                          close_reply.set_session_serviceid_timehiandver(serviceid_timehiandver);
                          close_reply.set_session_serviceid_cad_outsize(serviceid_clockseqandnode_outsize);
                          if (serviceid_clockseqandnode_outsize > 0 &&
                              serviceid_clockseqandnode != NULL
                                )
                          {
                             for (int i = 0; i < serviceid_clockseqandnode_outsize; i++)
                                close_reply.add_session_serviceid_clockseqandnode(serviceid_clockseqandnode[i]);
                          }
                          close_reply.set_session_opscnt(opscnt);
                          close_reply.set_session_head_next(head_next);
                          close_reply.set_session_head_prev(head_prev);
                          close_reply.set_session_context(session_context);

                          gettimeofday(&end, NULL);
                          int64_t i64Time;
                          i64Time = (end.tv_sec - start.tv_sec) * 1000000 +
                                    (end.tv_usec - start.tv_usec);
                          printf("gpp closesession used time: %ld us. \n", i64Time);

                          status_ = FINISH;

                          close_response.Finish(close_reply, Status::OK, this);
                       }
                    }else
                    {
                       std::cout << "gpp receive no closesession jwtsvid or validate jwt failed" << std::endl;
                       flag = 2;
                       close_reply.set_flag(flag);
                       status_ = FINISH;

                       close_response.Finish(close_reply, Status::OK, this);
                    }

                    break;
                 }

                 case ServerImpl::CallData::SS_TEECC_InvokeCommand:
                 {
                    struct timeval start, end, jwt_validate_start, jwt_validate_end, ltstart, ltend;
                    gettimeofday(&start, NULL);

                    std::uint32_t in_session_sessionid;
                    std::uint32_t in_session_serviceid_timelow;
                    std::uint32_t in_session_serviceid_timemid;
                    std::uint32_t in_session_serviceid_timehiandver;
                    std::uint32_t in_session_serviceid_clockseqandnode_size;
                    std::uint32_t *in_session_serviceid_clockseqandnode;
                    int in_session_serviceid_clockseqandnode_realsize;
                    std::uint32_t in_session_opscnt;
                    std::uint64_t in_session_head_next;
                    std::uint64_t in_session_head_prev;
                    std::uint64_t in_session_context;

                    std::uint32_t in_commandid;

                    std::uint32_t in_operation_started;
                    std::uint32_t in_operation_paramtypes;

                    std::uint64_t in_operation_param1_tmpref_buffer;
                    std::uint32_t in_operation_param1_tmpref_size;
                    std::uint64_t in_operation_param1_memref_parent;
                    std::uint32_t in_operation_param1_memref_parent_flag;
                    std::uint32_t in_operation_param1_memref_size;
                    std::uint32_t in_operation_param1_memref_offset;
                    std::uint32_t in_operation_param1_value_a;
                    std::uint32_t in_operation_param1_value_b;
                    std::int32_t in_operation_param1_ionref_ionsharefd;
                    std::uint32_t in_operation_param1_ionref_ionsize;

                    std::uint64_t in_operation_param2_tmpref_buffer;
                    std::uint32_t in_operation_param2_tmpref_size;
                    std::uint64_t in_operation_param2_memref_parent;
                    std::uint32_t in_operation_param2_memref_parent_flag;
                    std::uint32_t in_operation_param2_memref_size;
                    std::uint32_t in_operation_param2_memref_offset;
                    std::uint32_t in_operation_param2_value_a;
                    std::uint32_t in_operation_param2_value_b;
                    std::int32_t in_operation_param2_ionref_ionsharefd;
                    std::uint32_t in_operation_param2_ionref_ionsize;

                    std::uint64_t in_operation_param3_tmpref_buffer;
                    std::uint32_t in_operation_param3_tmpref_size;
                    std::uint64_t in_operation_param3_memref_parent;
                    std::uint32_t in_operation_param3_memref_parent_flag;
                    std::uint32_t in_operation_param3_memref_size;
                    std::uint32_t in_operation_param3_memref_offset;
                    std::uint32_t in_operation_param3_value_a;
                    std::uint32_t in_operation_param3_value_b;
                    std::int32_t in_operation_param3_ionref_ionsharefd;
                    std::uint32_t in_operation_param3_ionref_ionsize;

                    std::uint64_t in_operation_param4_tmpref_buffer;
                    std::uint32_t in_operation_param4_tmpref_size;
                    std::uint64_t in_operation_param4_memref_parent;
                    std::uint32_t in_operation_param4_memref_parent_flag;
                    std::uint32_t in_operation_param4_memref_size;
                    std::uint32_t in_operation_param4_memref_offset;
                    std::uint32_t in_operation_param4_value_a;
                    std::uint32_t in_operation_param4_value_b;
                    std::int32_t in_operation_param4_ionref_ionsharefd;
                    std::uint32_t in_operation_param4_ionref_ionsize;

                    std::uint64_t in_operation_session;
                    std::int32_t in_operation_cancelflag;

                    std::uint32_t in_returnorigin;

                    std::uint32_t in_buffer1_size;
                    std::uint32_t *in_buffer1;
                    int in_buffer1_realsize;
                    std::uint32_t in_buffer2_size;
                    std::uint32_t *in_buffer2;
                    int in_buffer2_realsize;
                    std::uint32_t in_buffer3_size;
                    std::uint32_t *in_buffer3;
                    int in_buffer3_realsize;
                    std::uint32_t in_buffer4_size;
                    std::uint32_t *in_buffer4;
                    int in_buffer4_realsize;

                    std::uint32_t teecresult;

                    std::uint32_t sessionid;
                    std::uint32_t serviceid_timelow;
                    std::uint32_t serviceid_timemid;
                    std::uint32_t serviceid_timehiandver;
                    std::uint32_t *serviceid_clockseqandnode;
                    int serviceid_clockseqandnode_realsize;
                    std::int32_t serviceid_clockseqandnode_outsize;
                    std::uint32_t opscnt;
                    std::uint64_t head_next;
                    std::uint64_t head_prev;
                    std::uint64_t session_context;
                    std::uint32_t started;
                    std::uint32_t paramtypes;
                    std::uint64_t operation_param1_tmpref_buffer;
                    std::uint32_t operation_param1_tmpref_size;
                    std::uint64_t operation_param1_memref_parent;
                    std::uint32_t operation_param1_memref_parent_flag;
                    std::uint32_t operation_param1_memref_size;
                    std::uint32_t operation_param1_memref_offset;
                    std::uint32_t operation_param1_value_a;
                    std::uint32_t operation_param1_value_b;
                    std::int32_t operation_param1_ionref_ionsharefd;
                    std::uint32_t operation_param1_ionref_ionsize;
                    std::uint64_t operation_param2_tmpref_buffer;
                    std::uint32_t operation_param2_tmpref_size;
                    std::uint64_t operation_param2_memref_parent;
                    std::uint32_t operation_param2_memref_parent_flag;
                    std::uint32_t operation_param2_memref_size;
                    std::uint32_t operation_param2_memref_offset;
                    std::uint32_t operation_param2_value_a;
                    std::uint32_t operation_param2_value_b;
                    std::int32_t operation_param2_ionref_ionsharefd;
                    std::uint32_t operation_param2_ionref_ionsize;
                    std::uint64_t operation_param3_tmpref_buffer;
                    std::uint32_t operation_param3_tmpref_size;
                    std::uint64_t operation_param3_memref_parent;
                    std::uint32_t operation_param3_memref_parent_flag;
                    std::uint32_t operation_param3_memref_size;
                    std::uint32_t operation_param3_memref_offset;
                    std::uint32_t operation_param3_value_a;
                    std::uint32_t operation_param3_value_b;
                    std::int32_t operation_param3_ionref_ionsharefd;
                    std::uint32_t operation_param3_ionref_ionsize;
                    std::uint64_t operation_param4_tmpref_buffer;
                    std::uint32_t operation_param4_tmpref_size;
                    std::uint64_t operation_param4_memref_parent;
                    std::uint32_t operation_param4_memref_parent_flag;
                    std::uint32_t operation_param4_memref_size;
                    std::uint32_t operation_param4_memref_offset;
                    std::uint32_t operation_param4_value_a;
                    std::uint32_t operation_param4_value_b;
                    std::int32_t operation_param4_ionref_ionsharefd;
                    std::uint32_t operation_param4_ionref_ionsize;
                    std::uint64_t operation_session;
                    std::int32_t operation_cancelflag;
                    std::uint32_t returnorigin;

                    std::uint32_t *buffer1;
                    int buffer1_realsize;
                    std::uint32_t buffer1_outsize;
                    std::uint32_t *buffer2;
                    int buffer2_realsize;
                    std::uint32_t buffer2_outsize;
                    std::uint32_t *buffer3;
                    int buffer3_realsize;
                    std::uint32_t buffer3_outsize;
                    std::uint32_t *buffer4;
                    int buffer4_realsize;
                    std::uint32_t buffer4_outsize;

                    std::uint32_t serial = 0;
                    std::int32_t flag = 0;
                    std::int32_t lt_flag = -1;
                    std::string token;


                    token = invo_request.token();

                    std::string noToken("noToken");
                    int ivaljwtResult = -1;
                    int iforceValidateJwt = global_force_valideta_jwt;

                    if
                          (
                          iforceValidateJwt == 1
                          &&
                          token.compare(noToken) != 0
                          )
                    {
                       char Token[1024];
                       strcpy(Token, (char *) token.data());
                       gettimeofday(&jwt_validate_start, NULL);
                       ivaljwtResult =
                             dbusmethodcall_validate_jwt(
                                   Token
                             );
                       gettimeofday(&jwt_validate_end, NULL);
                       int64_t i64Time_jwt;
                       i64Time_jwt = (jwt_validate_end.tv_sec - jwt_validate_start.tv_sec) * 1000000 +
                                     (jwt_validate_end.tv_usec - jwt_validate_start.tv_usec);
                       printf("gpp invokecommand validate jwt used time: %ld us. \n", i64Time_jwt);
                       std::cout << "gpp validate invokecommand jwtsvid" << std::endl;
                    } else
                    {
                       std::cout << "gpp no validate invokecommand jwtsvid" << std::endl;
                    }

                    if
                          (
                          iforceValidateJwt != 1
                          ||
                          (
                                iforceValidateJwt == 1
                                &&
                                token.compare(noToken) != 0
                                &&
                                ivaljwtResult == NO_ERROR
                          )
                          )
                    {
                       std::cout << "gpp does not need validate invokecommand jwtsvid or validate jwt succed"
                                 << std::endl;

                       in_session_sessionid = invo_request.in_session_sessionid();
                       in_session_serviceid_timelow = invo_request.in_session_serviceid_timelow();
                       in_session_serviceid_timemid = invo_request.in_session_serviceid_timemid();
                       in_session_serviceid_timehiandver = invo_request.in_session_serviceid_timehiandver();

                       in_session_serviceid_clockseqandnode_size = invo_request.in_session_serviceid_clockseqandnode_size();
                       in_session_serviceid_clockseqandnode_realsize = in_session_serviceid_clockseqandnode_size;
                       if (in_session_serviceid_clockseqandnode_size > 0)
                       {
                          in_session_serviceid_clockseqandnode = new uint32_t[in_session_serviceid_clockseqandnode_size];
                          for (int i = 0; i < in_session_serviceid_clockseqandnode_size; i++)
                          {
                             in_session_serviceid_clockseqandnode[i] = invo_request.in_session_serviceid_clockseqandnode(
                                   i);
                          }
                       }
                       in_session_opscnt = invo_request.in_session_opscnt();
                       in_session_head_next = invo_request.in_session_head_next();
                       in_session_head_prev = invo_request.in_session_head_prev();
                       in_session_context = invo_request.in_session_context();
                       in_commandid = invo_request.in_commandid();
                       in_operation_started = invo_request.in_operation_started();
                       in_operation_paramtypes = invo_request.in_operation_paramtypes();
                       in_operation_param1_tmpref_buffer = invo_request.in_operation_param1_tmpref_buffer();
                       in_operation_param1_tmpref_size = invo_request.in_operation_param1_tmpref_size();
                       in_operation_param1_memref_parent_flag = invo_request.in_operation_param1_memref_parent_flag();
                       in_operation_param1_memref_parent = invo_request.in_operation_param1_memref_parent();
                       in_operation_param1_memref_size = invo_request.in_operation_param1_memref_size();
                       in_operation_param1_memref_offset = invo_request.in_operation_param1_memref_offset();
                       in_operation_param1_value_a = invo_request.in_operation_param1_value_a();
                       in_operation_param1_value_b = invo_request.in_operation_param1_value_b();
                       in_operation_param1_ionref_ionsharefd = invo_request.in_operation_param1_ionref_ionsharefd();
                       in_operation_param1_ionref_ionsize = invo_request.in_operation_param1_ionref_ionsize();

                       in_operation_param2_tmpref_buffer = invo_request.in_operation_param2_tmpref_buffer();
                       in_operation_param2_tmpref_size = invo_request.in_operation_param2_tmpref_size();
                       in_operation_param2_memref_parent = invo_request.in_operation_param2_memref_parent();
                       in_operation_param2_memref_parent_flag = invo_request.in_operation_param2_memref_parent_flag();
                       in_operation_param2_memref_size = invo_request.in_operation_param2_memref_size();
                       in_operation_param2_memref_offset = invo_request.in_operation_param2_memref_offset();
                       in_operation_param2_value_a = invo_request.in_operation_param2_value_a();
                       in_operation_param2_value_b = invo_request.in_operation_param2_value_b();
                       in_operation_param2_ionref_ionsharefd = invo_request.in_operation_param2_ionref_ionsharefd();
                       in_operation_param2_ionref_ionsize = invo_request.in_operation_param2_ionref_ionsize();

                       in_operation_param3_tmpref_buffer = invo_request.in_operation_param3_tmpref_buffer();
                       in_operation_param3_tmpref_size = invo_request.in_operation_param3_tmpref_size();
                       in_operation_param3_memref_parent = invo_request.in_operation_param3_memref_parent();
                       in_operation_param3_memref_parent_flag = invo_request.in_operation_param3_memref_parent_flag();
                       in_operation_param3_memref_size = invo_request.in_operation_param3_memref_size();
                       in_operation_param3_memref_offset = invo_request.in_operation_param3_memref_offset();
                       in_operation_param3_value_a = invo_request.in_operation_param3_value_a();
                       in_operation_param3_value_b = invo_request.in_operation_param3_value_b();
                       in_operation_param3_ionref_ionsharefd = invo_request.in_operation_param3_ionref_ionsharefd();
                       in_operation_param3_ionref_ionsize = invo_request.in_operation_param3_ionref_ionsize();

                       in_operation_param4_tmpref_buffer = invo_request.in_operation_param4_tmpref_buffer();
                       in_operation_param4_tmpref_size = invo_request.in_operation_param4_tmpref_size();
                       in_operation_param4_memref_parent = invo_request.in_operation_param4_memref_parent();
                       in_operation_param4_memref_parent_flag = invo_request.in_operation_param4_memref_parent_flag();
                       in_operation_param4_memref_size = invo_request.in_operation_param4_memref_size();
                       in_operation_param4_memref_offset = invo_request.in_operation_param4_memref_offset();
                       in_operation_param4_value_a = invo_request.in_operation_param4_value_a();
                       in_operation_param4_value_b = invo_request.in_operation_param4_value_b();
                       in_operation_param4_ionref_ionsharefd = invo_request.in_operation_param4_ionref_ionsharefd();
                       in_operation_param4_ionref_ionsize = invo_request.in_operation_param4_ionref_ionsize();

                       in_operation_session = invo_request.in_operation_session();
                       in_operation_cancelflag = invo_request.in_operation_cancelflag();
                       in_returnorigin = invo_request.in_returnorigin();

                       in_buffer1_size = invo_request.in_buffer1_size();
                       in_buffer1_realsize = in_buffer1_size;
                       if (in_buffer1_size > 0)
                       {
                          in_buffer1 = new uint32_t[in_buffer1_size];
                          for (int i = 0; i < in_buffer1_size; i++)
                          {
                             in_buffer1[i] = invo_request.in_buffer1(i);
                          }
                       }

                       in_buffer2_size = invo_request.in_buffer2_size();
                       in_buffer2_realsize = in_buffer2_size;
                       if (in_buffer2_size > 0)
                       {
                          in_buffer2 = new uint32_t[in_buffer2_size];
                          for (int i = 0; i < in_buffer2_size; i++)
                          {
                             in_buffer2[i] = invo_request.in_buffer2(i);
                          }
                       }

                       in_buffer3_size = invo_request.in_buffer3_size();
                       in_buffer3_realsize = in_buffer3_size;
                       if (in_buffer3_size > 0)
                       {
                          in_buffer3 = new uint32_t[in_buffer3_size];
                          for (int i = 0; i < in_buffer3_size; i++)
                          {
                             in_buffer3[i] = invo_request.in_buffer3(i);
                          }
                       }

                       in_buffer4_size = invo_request.in_buffer4_size();
                       in_buffer4_realsize = in_buffer4_size;
                       if (in_buffer4_size > 0)
                       {
                          in_buffer4 = new uint32_t[in_buffer4_size];
                          for (int i = 0; i < in_buffer4_size; i++)
                          {
                             in_buffer4[i] = invo_request.in_buffer4(i);
                          }
                       }
                       lt_flag =invo_request.lt_flag();
                       std::cout << "gpp received InvokeCommand " << std::endl;
                       std::cout << "gpp received in_session_sessionid: 0x "
                                 << std::hex << std::setfill('0') << std::setw(8) << in_session_sessionid << std::endl;
#if 0
                       printf("   in_session_serviceid_timelow          = 0x %8.8x \n", in_session_serviceid_timelow);
                       printf("   in_session_serviceid_timemid          = 0x %8.8x \n", in_session_serviceid_timemid);
                       printf("   in_session_serviceid_timehiandver     = 0x %8.8x \n",
                              in_session_serviceid_timehiandver);
                       printf("   in_session_serviceid_clockseqandnode  = \n");
                       printf("   ");
                       for (int i = 0; i < in_session_serviceid_clockseqandnode_realsize; i++) {
                           printf(" %2.2x", in_session_serviceid_clockseqandnode[i]);
                       }
                       printf("\n");
                       printf("   in serviceid_clockseqandnode_size     = 0x %8.8x \n",
                         in_session_serviceid_clockseqandnode_size);
                       printf("   in_session_opscnt                     = 0x %8.8x \n", in_session_opscnt);
                       printf("   in_session_head_next                  = 0x %16.16lx \n", in_session_head_next);
                       printf("   in_session_head_prev                  = 0x %16.16lx \n", in_session_head_prev);
#endif
                       std::cout << "gpp received in_session_context: 0x " << std::hex << std::setfill('0')
                                 << std::setw(16) << in_session_context << std::endl;

#if 0
                       printf("   commandid                             = 0x %8.8x \n", in_commandid);
                       printf("   in_operation_started                  = 0x %8.8x \n", in_operation_started);
                       printf("   in_operation_paramtypes               = 0x %8.8x \n", in_operation_paramtypes);
                       printf("   in_operation_param1_tmpref_buffer     = 0x %16.16lx \n", in_operation_param1_tmpref_buffer);
                       printf("   in_operation_param1_tmpref_size       = 0x %8.8x \n", in_operation_param1_tmpref_size);
                       printf("   in_operation_param1_memref_parent     = 0x %16.16lx \n", in_operation_param1_memref_parent);
                       printf("   in_operation_param1_memref_size       = 0x %8.8x \n", in_operation_param1_memref_size);
                       printf("   in_operation_param1_memref_offset     = 0x %8.8x \n", in_operation_param1_memref_offset);
                       printf("   in_operation_param1_value_a           = 0x %8.8x \n", in_operation_param1_value_a);
                       printf("   in_operation_param1_value_b           = 0x %8.8x \n", in_operation_param1_value_b);
                       printf("   in_operation_param1_ionref_ionsharefd = 0x %8.8x \n",in_operation_param2_ionref_ionsharefd);
                       printf("   in_operation_param1_ionref_ionsize    = 0x %8.8x \n", in_operation_param2_ionref_ionsize);

                       printf("   in_operation_param2_tmpref_buffer     = 0x %16.16lx \n", in_operation_param2_tmpref_buffer);
                       printf("   in_operation_param2_tmpref_size       = 0x %8.8x \n", in_operation_param2_tmpref_size);
                       printf("   in_operation_param2_memref_parent     = 0x %16.16lx \n", in_operation_param2_memref_parent);
                       printf("   in_operation_param2_memref_size       = 0x %8.8x \n", in_operation_param2_memref_size);
                       printf("   in_operation_param2_memref_offset     = 0x %8.8x \n", in_operation_param2_memref_offset);
                       printf("   in_operation_param2_value_a           = 0x %8.8x \n", in_operation_param3_value_a);
                       printf("   in_operation_param2_value_b           = 0x %8.8x \n", in_operation_param3_value_b);
                       printf("   in_operation_param2_ionref_ionsharefd = 0x %8.8x \n", in_operation_param3_ionref_ionsharefd);
                       printf("   in_operation_param2_ionref_ionsize    = 0x %8.8x \n", in_operation_param3_ionref_ionsize);

                       printf("   in_operation_param3_tmpref_buffer     = 0x %16.16lx \n", in_operation_param3_tmpref_buffer);
                       printf("   in_operation_param3_tmpref_size       = 0x %8.8x \n", in_operation_param3_tmpref_size);
                       printf("   in_operation_param3_memref_parent     = 0x %16.16lx \n", in_operation_param3_memref_parent);
                       printf("   in_operation_param3_memref_size       = 0x %8.8x \n", in_operation_param3_memref_size);
                       printf("   in_operation_param3_memref_offset     = 0x %8.8x \n", in_operation_param3_memref_offset);
                       printf("   in_operation_param3_value_a           = 0x %8.8x \n", in_operation_param3_value_a);
                       printf("   in_operation_param3_value_b           = 0x %8.8x \n", in_operation_param3_value_b);
                       printf("   in_operation_param3_ionref_ionsharefd = 0x %8.8x \n", in_operation_param3_ionref_ionsharefd);
                       printf("   in_operation_param3_ionref_ionsize    = 0x %8.8x \n", in_operation_param3_ionref_ionsize);

                       printf("   in_operation_param4_tmpref_buffer     = 0x %16.16lx \n", in_operation_param4_tmpref_buffer);
                       printf("   in_operation_param4_tmpref_size       = 0x %8.8x \n", in_operation_param4_tmpref_size);
                       printf("   in_operation_param4_memref_parent     = 0x %16.16lx \n", in_operation_param4_memref_parent);
                       printf("   in_operation_param4_memref_size       = 0x %8.8x \n", in_operation_param4_memref_size);
                       printf("   in_operation_param4_memref_offset     = 0x %8.8x \n", in_operation_param4_memref_offset);
                       printf("   in_operation_param4_value_a           = 0x %8.8x \n", in_operation_param4_value_a);
                       printf("   in_operation_param4_value_b           = 0x %8.8x \n", in_operation_param4_value_b);
                       printf("   in_operation_param4_ionref_ionsharefd = 0x %8.8x \n", in_operation_param4_ionref_ionsharefd);
                       printf("   in_operation_param4_ionref_ionsize    = 0x %8.8x \n", in_operation_param4_ionref_ionsize);

                       printf("   in_operation_session                  = 0x %16.16lx \n", in_operation_session);
                       printf("   in_operation_cancelflag               = 0x %8.8x \n", in_operation_cancelflag);

                       printf("   in_returnorigin                       = 0x %8.8x \n", in_returnorigin);

                       printf("   in_buffer1                            = \n");
                       if (in_buffer1_size > 0) {
                          printf("   ");
                          for (int i = 0; i < in_buffer1_realsize; i++) {
                             printf(" %2.2x", in_buffer1[i]);
                          }
                          printf("\n");
                       }
#endif

#if 0
                       printf("   in_buffer1_size                       = 0x %8.8x \n",
                       in_buffer1_size);
#endif

#if 0
                       printf("   in_buffer2                            = \n");
                       if (in_buffer2_size > 0) {
                          printf("   ");
                          for (int i = 0; i < in_buffer2_realsize; i++) {
                             printf(" %2.2x", in_buffer2[i]);
                          }
                          printf("\n");
                       }
                       printf("   in_buffer2_size                       = 0x %8.8x \n",
                         in_buffer2_size);

                       printf("   in_buffer3                            = \n");
                       if (in_buffer3_size > 0) {
                          printf("   ");
                          for (int i = 0; i < in_buffer3_realsize; i++) {
                             printf(" %2.2x", in_buffer3[i]);
                          }
                          printf("\n");
                       }
                       printf("   in_buffer3_size                       = 0x %8.8x \n",
                         in_buffer3_size);

                       printf("   in_buffer4                            = \n");
                       if (in_buffer4_size > 0) {
                          printf("   ");
                          for (int i = 0; i < in_buffer4_realsize; i++) {
                             printf(" %2.2x", in_buffer4[i]);
                          }
                          printf("\n");
                       }
                       printf("   in_buffer4_size                       = 0x %8.8x \n",
                         in_buffer4_size);

#endif
                       if (in_buffer1_size > 0)
                       {
                       } else
                       {
                          in_buffer1_realsize = 0;
                       }
                       if (in_buffer2_size > 0)
                       {
                       } else
                       {
                          in_buffer2_realsize = 0;
                       }
                       if (in_buffer3_size > 0)
                       {
                       } else
                       {
                          in_buffer3_realsize = 0;
                       }
                       if (in_buffer4_size > 0)
                       {
                       } else
                       {
                          in_buffer4_realsize = 0;
                       }

                       serviceid_clockseqandnode_realsize = 8;
                       serviceid_clockseqandnode =
                             (uint32_t *) malloc(
                                   serviceid_clockseqandnode_realsize * sizeof(uint32_t)
                             );
                       uint32_t serviceid_clockseqandnode_outsize_temp;
                       uint32_t returnorigin_temp;

                       uint32_t *buffer1_temp = NULL;
                       uint32_t buffer1_size = 4096;
                       uint32_t buffer1_outsize_temp;
                       buffer1_temp =
                             (uint32_t *) malloc(buffer1_size * sizeof(uint32_t));

                       uint32_t buffer2_size = 4096;
                       uint32_t *buffer2_temp = NULL;
                       uint32_t buffer2_outsize_temp;
                       buffer2_temp =
                             (uint32_t *) malloc(buffer2_size * sizeof(uint32_t));

                       uint32_t buffer3_size = 4096;
                       uint32_t *buffer3_temp = NULL;
                       uint32_t buffer3_outsize_temp;
                       buffer3_temp =
                             (uint32_t *) malloc(buffer3_size * sizeof(uint32_t));

                       uint32_t buffer4_size = 4096;
                       uint32_t *buffer4_temp = NULL;
                       uint32_t buffer4_outsize_temp;
                       buffer4_temp =
                             (uint32_t *) malloc(buffer4_size * sizeof(uint32_t));

                       char workername[1024];
                       memset((char *) workername, 0, 1024);
                       int ifound = 0;
                       int iworker;
                       int lworker = -1;
                       sin_t *sinIns;
                       printf("gpproxy %d lt_flag = %d sessionid = 0x %8.8x \n",__LINE__,lt_flag,in_session_sessionid);
///////////////////////////////////////////////
                       if(lt_flag == 1)
                       {
                          gettimeofday(&ltstart, NULL);
                          printf("restore start gpproxy %d lt_flag = %d sessionid =  0x %8.8x \n",__LINE__,lt_flag,in_session_sessionid);
                          int ltworker;
                          pthread_mutex_lock(mutex_workerrec_);
                          for (iworker = 0; iworker < global_max_num_worker; iworker++)
                          {
                             if (ltworkerrec_[iworker].context_addr == in_session_context)
                             {
                                ltworker = iworker;
                                printf("find ltworker %d  = %d\n",ltworker);
                             }
                             if(workerrec_[iworker].context_addr == in_session_context)
                             {
                                lworker = iworker;
                                printf("find worker = %d\n",lworker);
                             }
                          }
                          sin_t *lsinIns;
                          sin_t *lsinInstemp;
                          lsinIns = ltworkerrec_[ltworker].first;
                          do
                          {
                             if(lsinIns->session_id == in_session_sessionid) break;
                             lsinIns = lsinIns->next;
                             if(lsinIns == NULL) {
                                std::cout << "live transfer error can't find session : " << in_session_sessionid << std::endl;
                                lsinIns = ltworkerrec_[ltworker].first;
                                while(lsinIns != NULL){
                                printf("tsnIns->self->session_id =  0x %8.8x \n",lsinIns->session_id);
                                lsinIns = lsinIns->next;
                                }
                             }
                          } while (lsinIns != NULL);
                          //lsinInstemp = lsinIns;
                          if(lsinIns->prev != NULL)
                          {
                             if(lsinIns->next == NULL){
                                lsinIns->prev->next = NULL;
                                ltworkerrec_[ltworker].last = lsinIns->prev;
                             }
                             if(lsinIns->next != NULL){
                                lsinIns->prev->next = lsinIns->next;
                                lsinIns->next->prev = lsinIns->prev;
                             }
                          }
                          if(lsinIns->prev == NULL)
                          {
                             if(lsinIns->next != NULL){
                                lsinIns->next->prev = NULL;
                                ltworkerrec_[ltworker].first = lsinIns->next;
                             }
                             if(lsinIns->next == NULL){
                                ltworkerrec_[ltworker].last = NULL;
                                ltworkerrec_[ltworker].first = NULL;
                             }
                          }
                          lsinIns->next = NULL;
                          lsinIns->prev = NULL;
                          ltworkerrec_[ltworker].sessionid_count =
                                ltworkerrec_[ltworker].sessionid_count - 1;
                          printf("gpproxy %d lt_flag = %d\n",__LINE__,lt_flag);

                          if(lworker != -1)
                          {
                             printf("gpproxy %d lt_flag = %d\n",__LINE__,lt_flag);
                             lsinIns->prev = workerrec_[lworker].last;
                             lsinIns->next = NULL;
                             workerrec_[lworker].last->next = lsinIns;
                             workerrec_[lworker].last = lsinIns;
                             workerrec_[lworker].sessionid_count =
                                   workerrec_[lworker].sessionid_count + 1;
                             lworker = -1;
                          }else
                          {
                             for (iworker = 0; iworker < global_max_num_worker; iworker++)
                             {
                                if (workerrec_[iworker].busy == 0)
                                {
                                   //std::memcpy(&workerrec_[iworker], &ltworkerrec_[ltworker],sizeof(wr_t));
                                   workerrec_[iworker].busy = ltworkerrec_[ltworker].busy;
                                   workerrec_[iworker].context_addr = ltworkerrec_[ltworker].context_addr;
                                   workerrec_[iworker].context_fd = ltworkerrec_[ltworker].context_fd;
                                   struct timeval ltvcreate;
                                   gettimeofday(&ltvcreate, NULL);
                                   workerrec_[iworker].context_createtime.tv_sec = ltvcreate.tv_sec;
                                   //workerrec_[iworker].first = ltworkerrec_[ltworker].first;
                                   //workerrec_[iworker].last = ltworkerrec_[ltworker].last;
                                   //workerrec_[iworker].sessionid_count = ltworkerrec_[ltworker].sessionid_count;
                                   if (workerrec_[iworker].first == NULL)
                                   {
                                      workerrec_[iworker].first = lsinIns;
                                      workerrec_[iworker].last = lsinIns;
                                      workerrec_[iworker].sessionid_count = 1;
                                   }
                                   std::cout << "ltvcreate.tv_sec " << ltvcreate.tv_sec << std::endl;
/*                                sin_t* current_session = workerrec_[iworker].first;
                                while (current_session != NULL) {
                                   std::memset(&current_session->session_createtime, 0, sizeof(current_session->session_createtime));
                                   current_session->session_createtime.tv_sec = ltvcreate.tv_sec;
                                   current_session = current_session->next;
                                }*/
                                //std::memset(&ltworkerrec_[ltworker], 0,sizeof(wr_t));
                                break;
                                }
                             }
                          }
                          printf("ltworkerrec_[ltworker].sessionid_count = %d \n",ltworkerrec_[ltworker].sessionid_count);
                          if(ltworkerrec_[ltworker].sessionid_count == 0)
                          {
                             printf("gpproxy  %d ltworkerrec clear lt_flag = %d\n",__LINE__,lt_flag);
                             ltworkerrec_[ltworker].busy = 0;
                             //pthread_cond_signal(cond_notbusy_);
                             ltworkerrec_[ltworker].context_fd = 0;
                             ltworkerrec_[ltworker].context_addr = 0xffffffff;
                             ltworkerrec_[ltworker].sessionid_count = 0;
                             sin_t *sinInstemp;
                             sin_t *sinInsPrevtemp;
                             sinInstemp = ltworkerrec_[ltworker].last;
                             if (sinInstemp != NULL)
                             {
                                for (;;)
                                {
                                   sinInsPrevtemp = sinInstemp->prev;
                                   free(sinInstemp);
                                   sinInstemp = sinInsPrevtemp;
                                   if (sinInstemp == NULL)
                                   {
                                      break;
                                   }
                                }
                             }
                          }
                          pthread_mutex_unlock(mutex_workerrec_);
                          gettimeofday(&ltend, NULL);
                          int zi64Time = (ltend.tv_sec - ltstart.tv_sec) * 1000000 +
                                    (ltend.tv_usec - ltstart.tv_usec);
                          printf("gpp huifu  xxxxxx  used time: %ld us. \n", zi64Time);
                       }
//////////////////////////////////////////////

                       pthread_mutex_lock(mutex_workerrec_);
                       for (iworker = 0; iworker < global_max_num_worker; iworker++)
                       {
                          if (workerrec_[iworker].context_addr == in_session_context)
                          {
                             sinIns = NULL;
                             if (workerrec_[iworker].first != NULL)
                             {
                                sinIns = workerrec_[iworker].first;
                                do
                                {
                                   if (sinIns->session_id == in_session_sessionid)
                                   {
                                      sprintf(workername, "%s%d", "gpworker", iworker);
                                      std::cout << "gpp method call worker No: " << std::dec << iworker << std::endl;
                                      printf("gpproxy session 0x %8.8x worker No: %d\n",in_session_sessionid,iworker);
                                      ifound = 1;
                                      break;
                                   }
                                   sinIns = sinIns->next;
                                } while (sinIns != NULL);
                                if (ifound == 1)
                                {
                                   break;
                                }
                             }
                          }
                       }
                       pthread_mutex_unlock(mutex_workerrec_);

                       if (ifound == 0)
                       {
                          printf("gpp can't find the worker for the session and the context. \n");

                          teecresult = 0xAAAA0017;

                          sessionid = 0x0;
                          serviceid_timelow = 0x0;
                          serviceid_timemid = 0x0;
                          serviceid_timehiandver = 0x0;
                          opscnt = 0x0;
                          head_next = 0x0;
                          head_prev = 0x0;
                          session_context = 0x0;
                          started = 0x0;
                          paramtypes = 0x0;

                          serviceid_clockseqandnode_realsize = 8;
                          serviceid_clockseqandnode =
                                (uint32_t *) malloc(
                                      serviceid_clockseqandnode_realsize * sizeof(uint32_t)
                                );
                          for (int i = 0; i < serviceid_clockseqandnode_realsize; i++)
                          {
                             serviceid_clockseqandnode[i] = 0x0;
                          }
                          serviceid_clockseqandnode_outsize = 8;

                          operation_param1_tmpref_buffer = 0x0;
                          operation_param1_tmpref_size = 0x0;
                          operation_param1_memref_parent = 0x0;
                          operation_param1_memref_size = 0x0;
                          operation_param1_memref_offset = 0x0;
                          operation_param1_value_a = 0x0;
                          operation_param1_value_b = 0x0;
                          operation_param1_ionref_ionsharefd = 0x0;
                          operation_param1_ionref_ionsize = 0x0;

                          operation_param2_tmpref_buffer = 0x0;
                          operation_param2_tmpref_size = 0x0;
                          operation_param2_memref_parent = 0x0;
                          operation_param2_memref_size = 0x0;
                          operation_param2_memref_offset = 0x0;
                          operation_param2_value_a = 0x0;
                          operation_param2_value_b = 0x0;
                          operation_param2_ionref_ionsharefd = 0x0;
                          operation_param2_ionref_ionsize = 0x0;

                          operation_param3_tmpref_buffer = 0x0;
                          operation_param3_tmpref_size = 0x0;
                          operation_param3_memref_parent = 0x0;
                          operation_param3_memref_size = 0x0;
                          operation_param3_memref_offset = 0x0;
                          operation_param3_value_a = 0x0;
                          operation_param3_value_b = 0x0;
                          operation_param3_ionref_ionsharefd = 0x0;
                          operation_param3_ionref_ionsize = 0x0;

                          operation_param4_tmpref_buffer = 0x0;
                          operation_param4_tmpref_size = 0x0;
                          operation_param4_memref_parent = 0x0;
                          operation_param4_memref_size = 0x0;
                          operation_param4_memref_offset = 0x0;
                          operation_param4_value_a = 0x0;
                          operation_param4_value_b = 0x0;
                          operation_param4_ionref_ionsharefd = 0x0;
                          operation_param4_ionref_ionsize = 0x0;

                          operation_session = 0x0;
                          operation_cancelflag = 0x0;

                          returnorigin = 0x0;

                          buffer1_realsize = 0;
                          buffer1_outsize = buffer1_realsize;

                          buffer2_realsize = 0;
                          buffer2_outsize = buffer2_realsize;

                          buffer3_realsize = 0;
                          buffer3_outsize = buffer3_realsize;

                          buffer4_realsize = 0;
                          buffer4_outsize = buffer4_realsize;

                          invo_reply.set_teecresult(teecresult);
                          invo_reply.set_session_sessionid(sessionid);
                          invo_reply.set_session_serviceid_timelow(serviceid_timelow);
                          invo_reply.set_session_serviceid_timemid(serviceid_timemid);
                          invo_reply.set_session_serviceid_timehiandver(serviceid_timehiandver);
                          invo_reply.set_session_serviceid_clockseqandnode_outsize(serviceid_clockseqandnode_outsize);
                          if (serviceid_clockseqandnode_outsize > 0 &&
                              serviceid_clockseqandnode != NULL
                                )
                          {
                             for (int i = 0; i < serviceid_clockseqandnode_outsize; i++)
                                invo_reply.add_session_serviceid_clockseqandnode(serviceid_clockseqandnode[i]);
                          }
                          invo_reply.set_session_opscnt(opscnt);
                          invo_reply.set_session_head_next(head_next);
                          invo_reply.set_session_head_prev(head_prev);
                          invo_reply.set_session_context(session_context);
                          invo_reply.set_operation_started(started);
                          invo_reply.set_operation_paramtypes(paramtypes);

                          invo_reply.set_operation_param1_tmpref_buffer(operation_param1_tmpref_buffer);
                          invo_reply.set_operation_param1_tmpref_size(operation_param1_tmpref_size);
                          invo_reply.set_operation_param1_memref_parent(operation_param1_memref_parent);
                          invo_reply.set_operation_param1_memref_parent_flag(in_operation_param1_memref_parent_flag);
                          invo_reply.set_operation_param1_memref_size(operation_param1_memref_size);
                          invo_reply.set_operation_param1_memref_offset(operation_param1_memref_offset);
                          invo_reply.set_operation_param1_value_a(operation_param1_value_a);
                          invo_reply.set_operation_param1_value_b(operation_param1_value_b);
                          invo_reply.set_operation_param1_ionref_ionsharefd(operation_param1_ionref_ionsharefd);
                          invo_reply.set_operation_param1_ionref_ionsize(operation_param1_ionref_ionsize);

                          invo_reply.set_operation_param2_tmpref_buffer(operation_param2_tmpref_buffer);
                          invo_reply.set_operation_param2_tmpref_size(operation_param2_tmpref_size);
                          invo_reply.set_operation_param2_memref_parent(operation_param2_memref_parent);
                          invo_reply.set_operation_param2_memref_parent_flag(in_operation_param2_memref_parent_flag);
                          invo_reply.set_operation_param2_memref_size(operation_param2_memref_size);
                          invo_reply.set_operation_param2_memref_offset(operation_param2_memref_offset);
                          invo_reply.set_operation_param2_value_a(operation_param2_value_a);
                          invo_reply.set_operation_param2_value_b(operation_param2_value_b);
                          invo_reply.set_operation_param2_ionref_ionsharefd(operation_param2_ionref_ionsharefd);
                          invo_reply.set_operation_param2_ionref_ionsize(operation_param2_ionref_ionsize);

                          invo_reply.set_operation_param3_tmpref_buffer(operation_param3_tmpref_buffer);
                          invo_reply.set_operation_param3_tmpref_size(operation_param3_tmpref_size);
                          invo_reply.set_operation_param3_memref_parent(operation_param3_memref_parent);
                          invo_reply.set_operation_param3_memref_parent_flag(in_operation_param3_memref_parent_flag);
                          invo_reply.set_operation_param3_memref_size(operation_param3_memref_size);
                          invo_reply.set_operation_param3_memref_offset(operation_param3_memref_offset);
                          invo_reply.set_operation_param3_value_a(operation_param3_value_a);
                          invo_reply.set_operation_param3_value_b(operation_param3_value_b);
                          invo_reply.set_operation_param3_ionref_ionsharefd(operation_param3_ionref_ionsharefd);
                          invo_reply.set_operation_param3_ionref_ionsize(operation_param3_ionref_ionsize);

                          invo_reply.set_operation_param4_tmpref_buffer(operation_param4_tmpref_buffer);
                          invo_reply.set_operation_param4_tmpref_size(operation_param4_tmpref_size);
                          invo_reply.set_operation_param4_memref_parent(operation_param4_memref_parent);
                          invo_reply.set_operation_param4_memref_parent_flag(in_operation_param4_memref_parent_flag);
                          invo_reply.set_operation_param4_memref_size(operation_param4_memref_size);
                          invo_reply.set_operation_param4_memref_offset(operation_param4_memref_offset);
                          invo_reply.set_operation_param4_value_a(operation_param4_value_a);
                          invo_reply.set_operation_param4_value_b(operation_param4_value_b);
                          invo_reply.set_operation_param4_ionref_ionsharefd(operation_param4_ionref_ionsharefd);
                          invo_reply.set_operation_param4_ionref_ionsize(operation_param4_ionref_ionsize);

                          invo_reply.set_operation_session(operation_session);
                          invo_reply.set_operation_cancelflag(operation_cancelflag);
                          invo_reply.set_returnorigin(returnorigin);

                          invo_reply.set_buffer1_outsize(buffer1_realsize);
                          invo_reply.set_buffer2_outsize(buffer2_realsize);
                          invo_reply.set_buffer3_outsize(buffer3_realsize);
                          invo_reply.set_buffer4_outsize(buffer4_realsize);

                          if (buffer1_realsize > 0 &&
                              buffer1 != NULL
                                )
                          {
                             for (int i = 0; i < buffer1_realsize; i++)

                                invo_reply.add_buffer1(buffer1[i]);
                          }

                          if (buffer2_realsize > 0 &&
                              buffer2 != NULL
                                )
                          {
                             for (int i = 0; i < buffer2_realsize; i++)
                                invo_reply.add_buffer2(buffer2[i]);
                          }

                          if (buffer3_realsize > 0 &&
                              buffer3 != NULL
                                )
                          {
                             for (int i = 0; i < buffer3_realsize; i++)
                                invo_reply.add_buffer3(buffer3[i]);
                          }

                          if (buffer4_realsize > 0 &&
                              buffer4 != NULL
                                )
                          {
                             for (int i = 0; i < buffer4_realsize; i++)
                                invo_reply.add_buffer4(buffer4[i]);
                          }
                          status_ = FINISH;

                          invo_response.Finish(invo_reply, Status::OK, this);
                       }else
                       {
                          method_call_teec_invokecommand(
                                workername,

                                in_session_sessionid,
                                in_session_serviceid_timelow,
                                in_session_serviceid_timemid,
                                in_session_serviceid_timehiandver,
                                in_session_serviceid_clockseqandnode,
                                in_session_serviceid_clockseqandnode_realsize,
                                in_session_opscnt,
                                in_session_head_next,
                                in_session_head_prev,
                                in_session_context,

                                in_commandid,

                                in_operation_started,
                                in_operation_paramtypes,

                                in_operation_param1_tmpref_buffer,
                                in_operation_param1_tmpref_size,
                                in_operation_param1_memref_parent,
                                in_operation_param1_memref_parent_flag,
                                in_operation_param1_memref_size,
                                in_operation_param1_memref_offset,
                                in_operation_param1_value_a,
                                in_operation_param1_value_b,
                                in_operation_param1_ionref_ionsharefd,
                                in_operation_param1_ionref_ionsize,

                                in_operation_param2_tmpref_buffer,
                                in_operation_param2_tmpref_size,
                                in_operation_param2_memref_parent,
                                in_operation_param2_memref_parent_flag,
                                in_operation_param2_memref_size,
                                in_operation_param2_memref_offset,
                                in_operation_param2_value_a,
                                in_operation_param2_value_b,
                                in_operation_param2_ionref_ionsharefd,
                                in_operation_param2_ionref_ionsize,

                                in_operation_param3_tmpref_buffer,
                                in_operation_param3_tmpref_size,
                                in_operation_param3_memref_parent,
                                in_operation_param3_memref_parent_flag,
                                in_operation_param3_memref_size,
                                in_operation_param3_memref_offset,
                                in_operation_param3_value_a,
                                in_operation_param3_value_b,
                                in_operation_param3_ionref_ionsharefd,
                                in_operation_param3_ionref_ionsize,

                                in_operation_param4_tmpref_buffer,
                                in_operation_param4_tmpref_size,
                                in_operation_param4_memref_parent,
                                in_operation_param4_memref_parent_flag,
                                in_operation_param4_memref_size,
                                in_operation_param4_memref_offset,
                                in_operation_param4_value_a,
                                in_operation_param4_value_b,
                                in_operation_param4_ionref_ionsharefd,
                                in_operation_param4_ionref_ionsize,

                                in_operation_session,
                                in_operation_cancelflag,

                                in_returnorigin,

                                in_buffer1,
                                in_buffer1_realsize,
                                in_buffer2,
                                in_buffer2_realsize,
                                in_buffer3,
                                in_buffer3_realsize,
                                in_buffer4,
                                in_buffer4_realsize,

                                lt_flag,

                                &teecresult,

                                &sessionid,
                                &serviceid_timelow,
                                &serviceid_timemid,
                                &serviceid_timehiandver,
                                serviceid_clockseqandnode,
                                serviceid_clockseqandnode_realsize,
                                &serviceid_clockseqandnode_outsize_temp,

                                &opscnt,
                                &head_next,
                                &head_prev,
                                &session_context,

                                &started,
                                &paramtypes,

                                &operation_param1_tmpref_buffer,
                                &operation_param1_tmpref_size,
                                &operation_param1_memref_parent,
                                &operation_param1_memref_parent_flag,
                                &operation_param1_memref_size,
                                &operation_param1_memref_offset,
                                &operation_param1_value_a,
                                &operation_param1_value_b,
                                &operation_param1_ionref_ionsharefd,
                                &operation_param1_ionref_ionsize,

                                &operation_param2_tmpref_buffer,
                                &operation_param2_tmpref_size,
                                &operation_param2_memref_parent,
                                &operation_param2_memref_parent_flag,
                                &operation_param2_memref_size,
                                &operation_param2_memref_offset,
                                &operation_param2_value_a,
                                &operation_param2_value_b,
                                &operation_param2_ionref_ionsharefd,
                                &operation_param2_ionref_ionsize,

                                &operation_param3_tmpref_buffer,
                                &operation_param3_tmpref_size,
                                &operation_param3_memref_parent,
                                &operation_param3_memref_parent_flag,
                                &operation_param3_memref_size,
                                &operation_param3_memref_offset,
                                &operation_param3_value_a,
                                &operation_param3_value_b,
                                &operation_param3_ionref_ionsharefd,
                                &operation_param3_ionref_ionsize,

                                &operation_param4_tmpref_buffer,
                                &operation_param4_tmpref_size,
                                &operation_param4_memref_parent,
                                &operation_param4_memref_parent_flag,
                                &operation_param4_memref_size,
                                &operation_param4_memref_offset,
                                &operation_param4_value_a,
                                &operation_param4_value_b,
                                &operation_param4_ionref_ionsharefd,
                                &operation_param4_ionref_ionsize,

                                &operation_session,
                                &operation_cancelflag,

                                &returnorigin_temp,

                                buffer1_temp,
                                buffer1_size,
                                &buffer1_outsize_temp,
                                buffer2_temp,
                                buffer2_size,
                                &buffer2_outsize_temp,
                                buffer3_temp,
                                buffer3_size,
                                &buffer3_outsize_temp,
                                buffer4_temp,
                                buffer4_size,
                                &buffer4_outsize_temp
                          );
                          //printf("gpproxy %d lt_flag = %d\n",__LINE__,lt_flag);

                          pthread_mutex_lock(mutex_workerrec_);
                          struct timeval tvcreate;
                          gettimeofday(&tvcreate, NULL);
                          workerrec_[iworker].context_createtime = tvcreate;
                          sinIns->session_createtime = tvcreate;
                          pthread_mutex_unlock(mutex_workerrec_);

                          serviceid_clockseqandnode_outsize =
                                serviceid_clockseqandnode_outsize_temp;

                          returnorigin = returnorigin_temp;

                          buffer1_outsize = buffer1_outsize_temp;
                          buffer2_outsize = buffer2_outsize_temp;
                          buffer3_outsize = buffer3_outsize_temp;
                          buffer4_outsize = buffer4_outsize_temp;


                          buffer1_realsize = buffer1_outsize;
                          if (buffer1_realsize > 0)
                          {
                             buffer1 =
                                   (uint32_t *) malloc(
                                         buffer1_realsize * sizeof(uint32_t)
                                   );
                             for (int i = 0; i < buffer1_realsize; i++)
                             {
                                buffer1[i] = (uint32_t) buffer1_temp[i];
                             }
                          }
                          buffer2_realsize = buffer2_outsize;
                          if (buffer2_realsize > 0)
                          {
                             buffer2 =
                                   (uint32_t *) malloc(
                                         buffer2_realsize * sizeof(uint32_t)
                                   );
                             for (int i = 0; i < buffer2_realsize; i++)
                             {
                                buffer2[i] = (uint32_t) buffer2_temp[i];
                             }
                          }

                          buffer3_realsize = buffer3_outsize;
                          if (buffer3_realsize > 0)
                          {
                             buffer3 =
                                   (uint32_t *) malloc(
                                         buffer3_realsize * sizeof(uint32_t)
                                   );
                             for (int i = 0; i < buffer3_realsize; i++)
                             {
                                buffer3[i] = (uint32_t) buffer3_temp[i];
                             }
                          }

                          buffer4_realsize = buffer4_outsize;
                          if (buffer4_realsize > 0)
                          {
                             buffer4 =
                                   (uint32_t *) malloc(
                                         buffer4_realsize * sizeof(uint32_t)
                                   );
                             for (int i = 0; i < buffer4_realsize; i++)
                             {
                                buffer4[i] = (uint32_t) buffer4_temp[i];
                             }
                          }
                          if (buffer1_temp != NULL)
                          {
                             free(buffer1_temp);
                          }
                          if (buffer2_temp != NULL)
                          {
                             free(buffer2_temp);
                          }
                          if (buffer3_temp != NULL)
                          {
                             free(buffer3_temp);
                          }
                          if (buffer4_temp != NULL)
                          {
                             free(buffer4_temp);
                          }

                          invo_reply.set_teecresult(teecresult);
                          invo_reply.set_session_sessionid(sessionid);
                          invo_reply.set_session_serviceid_timelow(serviceid_timelow);
                          invo_reply.set_session_serviceid_timemid(serviceid_timemid);
                          invo_reply.set_session_serviceid_timehiandver(serviceid_timehiandver);
                          invo_reply.set_session_serviceid_clockseqandnode_outsize(serviceid_clockseqandnode_outsize);

                          if (serviceid_clockseqandnode_outsize > 0 &&
                              serviceid_clockseqandnode != NULL
                                )
                          {
                             for (int i = 0; i < serviceid_clockseqandnode_outsize; i++)
                                invo_reply.add_session_serviceid_clockseqandnode(serviceid_clockseqandnode[i]);
                          }
                          invo_reply.set_session_opscnt(opscnt);
                          invo_reply.set_session_head_next(head_next);
                          invo_reply.set_session_head_prev(head_prev);
                          invo_reply.set_session_context(session_context);
                          invo_reply.set_operation_started(started);
                          invo_reply.set_operation_paramtypes(paramtypes);

                          invo_reply.set_operation_param1_tmpref_buffer(operation_param1_tmpref_buffer);
                          invo_reply.set_operation_param1_tmpref_size(operation_param1_tmpref_size);
                          invo_reply.set_operation_param1_memref_parent(operation_param1_memref_parent);
                          invo_reply.set_operation_param1_memref_parent_flag(in_operation_param1_memref_parent_flag);
                          invo_reply.set_operation_param1_memref_size(operation_param1_memref_size);
                          invo_reply.set_operation_param1_memref_offset(operation_param1_memref_offset);
                          invo_reply.set_operation_param1_value_a(operation_param1_value_a);
                          invo_reply.set_operation_param1_value_b(operation_param1_value_b);
                          invo_reply.set_operation_param1_ionref_ionsharefd(operation_param1_ionref_ionsharefd);
                          invo_reply.set_operation_param1_ionref_ionsize(operation_param1_ionref_ionsize);

                          invo_reply.set_operation_param2_tmpref_buffer(operation_param2_tmpref_buffer);
                          invo_reply.set_operation_param2_tmpref_size(operation_param2_tmpref_size);
                          invo_reply.set_operation_param2_memref_parent(operation_param2_memref_parent);
                          invo_reply.set_operation_param2_memref_parent_flag(in_operation_param2_memref_parent_flag);
                          invo_reply.set_operation_param2_memref_size(operation_param2_memref_size);
                          invo_reply.set_operation_param2_memref_offset(operation_param2_memref_offset);
                          invo_reply.set_operation_param2_value_a(operation_param2_value_a);
                          invo_reply.set_operation_param2_value_b(operation_param2_value_b);
                          invo_reply.set_operation_param2_ionref_ionsharefd(operation_param2_ionref_ionsharefd);
                          invo_reply.set_operation_param2_ionref_ionsize(operation_param2_ionref_ionsize);

                          invo_reply.set_operation_param3_tmpref_buffer(operation_param3_tmpref_buffer);
                          invo_reply.set_operation_param3_tmpref_size(operation_param3_tmpref_size);
                          invo_reply.set_operation_param3_memref_parent(operation_param3_memref_parent);
                          invo_reply.set_operation_param3_memref_parent_flag(in_operation_param3_memref_parent_flag);
                          invo_reply.set_operation_param3_memref_size(operation_param3_memref_size);
                          invo_reply.set_operation_param3_memref_offset(operation_param3_memref_offset);
                          invo_reply.set_operation_param3_value_a(operation_param3_value_a);
                          invo_reply.set_operation_param3_value_b(operation_param3_value_b);
                          invo_reply.set_operation_param3_ionref_ionsharefd(operation_param3_ionref_ionsharefd);
                          invo_reply.set_operation_param3_ionref_ionsize(operation_param3_ionref_ionsize);

                          invo_reply.set_operation_param4_tmpref_buffer(operation_param4_tmpref_buffer);
                          invo_reply.set_operation_param4_tmpref_size(operation_param4_tmpref_size);
                          invo_reply.set_operation_param4_memref_parent(operation_param4_memref_parent);
                          invo_reply.set_operation_param4_memref_parent_flag(in_operation_param4_memref_parent_flag);
                          invo_reply.set_operation_param4_memref_size(operation_param4_memref_size);
                          invo_reply.set_operation_param4_memref_offset(operation_param4_memref_offset);
                          invo_reply.set_operation_param4_value_a(operation_param4_value_a);
                          invo_reply.set_operation_param4_value_b(operation_param4_value_b);
                          invo_reply.set_operation_param4_ionref_ionsharefd(operation_param4_ionref_ionsharefd);
                          invo_reply.set_operation_param4_ionref_ionsize(operation_param4_ionref_ionsize);

                          invo_reply.set_operation_session(operation_session);
                          invo_reply.set_operation_cancelflag(operation_cancelflag);
                          invo_reply.set_returnorigin(returnorigin);

                          invo_reply.set_buffer1_outsize(buffer1_realsize);
                          invo_reply.set_buffer2_outsize(buffer2_realsize);
                          invo_reply.set_buffer3_outsize(buffer3_realsize);
                          invo_reply.set_buffer4_outsize(buffer4_realsize);

                          if (buffer1_realsize > 0 &&
                              buffer1 != NULL
                                )
                          {
                             for (int i = 0; i < buffer1_realsize; i++)

                                invo_reply.add_buffer1(buffer1[i]);
                          }

                          if (buffer2_realsize > 0 &&
                              buffer2 != NULL
                                )
                          {
                             for (int i = 0; i < buffer2_realsize; i++)
                                invo_reply.add_buffer2(buffer2[i]);
                          }

                          if (buffer3_realsize > 0 &&
                              buffer3 != NULL
                                )
                          {
                             for (int i = 0; i < buffer3_realsize; i++)
                                invo_reply.add_buffer3(buffer3[i]);
                          }

                          if (buffer4_realsize > 0 &&
                              buffer4 != NULL
                                )
                          {
                             for (int i = 0; i < buffer4_realsize; i++)
                                invo_reply.add_buffer4(buffer4[i]);
                          }
                          status_ = FINISH;
                          gettimeofday(&end, NULL);
                          int64_t i64Time;
                          i64Time = (end.tv_sec - start.tv_sec) * 1000000 +
                                    (end.tv_usec - start.tv_usec);
                          printf("gpp invokecommand used time: %ld us. \n", i64Time);
                          invo_response.Finish(invo_reply, Status::OK, this);
/////////////////////////////////////////////////////////////////
                          if(lt_flag == 0){
                             gettimeofday(&ltstart, NULL);
                             printf("live transfer store start sessionid = 0x %8.8x\n",in_session_sessionid);
                             pthread_mutex_lock(mutex_workerrec_);
                             for (int ltworker = 0; ltworker < global_max_num_worker; ltworker++)
                             {
                                if(ltworkerrec_[ltworker].context_addr == workerrec_[iworker].context_addr)
                                {
                                   sin_t *ltsinIns = (sin_t *) malloc(sizeof(sin_t));
                                   ltsinIns->session_id = sinIns->session_id;
                                   ltsinIns->prev = ltworkerrec_[ltworker].last;
                                   ltsinIns->next = NULL;
                                   ltworkerrec_[ltworker].last->next = ltsinIns;
                                   ltworkerrec_[ltworker].last = ltsinIns;
                                   ltworkerrec_[ltworker].sessionid_count =
                                         ltworkerrec_[ltworker].sessionid_count + 1;
                                   printf("store ltworkerrec_[ltworker].session_id =  0x %8.8x \n",ltsinIns->session_id);

                                   sin_t *sinTemp;
                                   sinTemp = sinIns->prev;
                                   if (sinTemp != NULL)
                                   {
                                      sinTemp->next = sinIns->next;
                                   }
                                   sinTemp = sinIns->next;
                                   if (sinTemp != NULL)
                                   {
                                      sinTemp->prev = sinIns->prev;
                                   }
                                   if (workerrec_[iworker].last == sinIns)
                                   {
                                      workerrec_[iworker].last = sinIns->prev;
                                   }
                                   if (workerrec_[iworker].first == sinIns)
                                   {
                                      workerrec_[iworker].first = sinIns->next;
                                   }
                                   free(sinIns);
                                   workerrec_[iworker].sessionid_count =
                                         workerrec_[iworker].sessionid_count - 1;
                                   std::cout << "workerrec_[" << iworker << "].sessionid_count = " << (int) workerrec_[iworker].sessionid_count << std::endl;
                                   break;
                                }
                                int worker_end = global_max_num_worker - 1;
                                if(ltworker == worker_end)
                                {
                                   for (int jworker = 0; jworker < global_max_num_worker; jworker++)
                                   {
                                      if(ltworkerrec_[jworker].busy == 0)
                                      {
                                         //std::memcpy(&ltworkerrec_[ltworker], &workerrec_[iworker],sizeof(wr_t));
                                         ltworkerrec_[jworker].busy = workerrec_[iworker].busy;
                                         ltworkerrec_[jworker].context_addr = workerrec_[iworker].context_addr;
                                         ltworkerrec_[jworker].context_fd = workerrec_[iworker].context_fd;
                                         sin_t *ltsinIns = (sin_t *) malloc(sizeof(sin_t));
                                         ltsinIns->session_id = sinIns->session_id;
                                         ltsinIns->next = NULL;
                                         ltsinIns->prev = NULL;
                                         ltworkerrec_[jworker].first = ltsinIns;
                                         ltworkerrec_[jworker].last = ltsinIns;
                                         ltworkerrec_[jworker].sessionid_count = 1;
                                         std::cout << "ltworkerrec_[" << jworker << "].busy = " << (int) ltworkerrec_[jworker].busy << std::endl;
                                         printf("store ltworkerrec_[ltworker].session_id =  0x %8.8x \n",ltsinIns->session_id);

                                         sin_t *sinTemp;
                                         sinTemp = sinIns->prev;
                                         if (sinTemp != NULL)
                                         {
                                            sinTemp->next = sinIns->next;
                                         }
                                         sinTemp = sinIns->next;
                                         if (sinTemp != NULL)
                                         {
                                            sinTemp->prev = sinIns->prev;
                                         }
                                         if (workerrec_[iworker].last == sinIns)
                                         {
                                            workerrec_[iworker].last = sinIns->prev;
                                         }
                                         if (workerrec_[iworker].first == sinIns)
                                         {
                                            workerrec_[iworker].first = sinIns->next;
                                         }
                                         free(sinIns);
                                         std::cout << "workerrec_[" << iworker << "].sessionid_count = " << (int) workerrec_[iworker].sessionid_count << std::endl;
                                         workerrec_[iworker].sessionid_count =
                                               workerrec_[iworker].sessionid_count - 1;
                                         std::cout << "workerrec_[" << iworker << "].busy = " << (int) workerrec_[iworker].busy << std::endl;
                                         printf("gpproxy %d \n",__LINE__);
                                         break;
                                      }
                                      if(jworker == global_max_num_worker - 1){
                                         printf("live transfer store  sessionid : 0x %8.8x error ltworkerrec is full \n",in_session_sessionid);
                                         lt_flag = -2;
                                      }
                                   }
                                }
                             }
                             if(workerrec_[iworker].sessionid_count == 0)
                             {
                                printf("gpproxy worker %d clear  %d \n",iworker,__LINE__);
                                workerrec_[iworker].busy = 0;
                                pthread_cond_signal(cond_notbusy_);
                                workerrec_[iworker].context_fd = 0;
                                workerrec_[iworker].context_addr = 0xffffffff;
                                workerrec_[iworker].sessionid_count = 0;
                                sin_t *sinInstemp;
                                sin_t *sinInsPrevtemp;
                                sinInstemp = workerrec_[iworker].last;
                                if (sinInstemp != NULL)
                                {
                                   for (;;)
                                   {
                                      sinInsPrevtemp = sinInstemp->prev;
                                      free(sinInstemp);
                                      sinInstemp = sinInsPrevtemp;
                                      if (sinInstemp == NULL)
                                      {
                                         break;
                                      }
                                   }
                                }
                             }
                             pthread_mutex_unlock(mutex_workerrec_);
                             gettimeofday(&ltend, NULL);
                             i64Time = (ltend.tv_sec - ltstart.tv_sec) * 1000000 +
                                       (ltend.tv_usec - ltstart.tv_usec);
                             printf("gpp baocun xxxxxx  used time: %ld us. \n", i64Time);

                             //sleep(10);
                          }
////////////////////////////////////////////////////////////////
                       }
                       printf("gpproxy session 0x %8.8x over\n",in_session_sessionid);
                    }else
                    {
                       std::cout << "gpp receive no invokecommand jwtsvid or validate jwt failed" << std::endl;
                       flag = 2;
                       invo_reply.set_flag(flag);
                       status_ = FINISH;
                       invo_response.Finish(invo_reply, Status::OK, this);
                    }
                    break;
                 }

                 case ServerImpl::CallData::SS_TEECC_TA:
                 {
                    std::string token;
                    token = ta_chunk.token();
                    std::int32_t flag = 0;

                    std::string noToken("noToken");
                    int ivaljwtResult = -1;
                    int iforceValidateJwt = global_force_valideta_jwt;

                    if
                          (
                          iforceValidateJwt == 1
                          &&
                          token.compare(noToken) != 0
                          )
                    {
                       char Token[1024];
                       strcpy(Token, (char *) token.data());
                       ivaljwtResult =
                             dbusmethodcall_validate_jwt(
                                   Token
                             );
                       std::cout << "gpp validate deployta jwtsvid" << std::endl;
                    } else
                    {
                       std::cout << "gpp no validate deployta jwtsvid" << std::endl;
                    }

                    if
                          (
                          iforceValidateJwt != 1
                          ||
                          (
                                iforceValidateJwt == 1
                                &&
                                token.compare(noToken) != 0
                                &&
                                ivaljwtResult == NO_ERROR
                          )
                          )
                    {
                       std::cout << "gpp does not need validate deployta jwtsvid or validate jwt succed" << std::endl;
                       std::cout << "gpp received deployta " << std::endl;

                       std::string remote_sha256 = ta_chunk.sha256();

                       std::string subdir = ta_chunk.subdir();

                       std::string name = ta_chunk.name();
                       name = "/data/" + subdir + "/" + name;
                       const char *filename = name.data();

                       std::cout << "gpp deployta, full namepath: " << name << std::endl;

                       if (access(name.c_str(), F_OK) != -1)
                       {
                          std::cout << "gpp deloyta: ta file exist" << std::endl;

                          char *name_temp = const_cast<char *>(name.data());
                          char local_sha256_temp[SHA256_LENTH];
                          int iRet;
                          iRet = get_file_sha256((char *) name_temp, local_sha256_temp);
                          if (iRet != 0)
                          {
                             ta_reply.set_code(-2);
                             status_ = FINISH;

                             ta_response.Finish(ta_reply, Status::OK, this);
                          } else
                          {

                             char remote_sha256_temp[SHA256_LENTH + 1];
                             strcpy(remote_sha256_temp, remote_sha256.c_str());

                             if (memcmp(local_sha256_temp, remote_sha256_temp, SHA256_LENTH) == 0)
                             {
                                std::cout << "gpp deloyta: sha256 vals are the same" << std::endl;

                                status_ = FINISH;
                                ta_reply.set_code(0);

                                ta_response.Finish(ta_reply, Status::OK, this);
                             } else
                             {
                                std::cout << "gpp deloyta: sha256 vals are different, replace " << filename
                                          << std::endl;

                                std::ofstream outfile;
                                outfile.open(filename,
                                             std::ofstream::out | std::ofstream::trunc | std::ofstream::binary);

                                const char *data;
                                data = ta_chunk.buffer().c_str();
                                outfile.write(data, ta_chunk.buffer().length());
                                outfile.close();

                                status_ = FINISH;
                                ta_reply.set_code(0);

                                ta_response.Finish(ta_reply, Status::OK, this);
                             }

                          }
                       } else
                       {
                          std::string wholedir;
                          wholedir = "/data/" + subdir;
                          const char *charwholedir = wholedir.data();

                          std::cout << "gpp deployta, wholedir: " << wholedir << std::endl;

                          struct stat st = {0};
                          if (stat(charwholedir, &st) == -1)
                          {
                             std::cout << "gpp deployta, make a new dir " << wholedir << std::endl;

                             int iResult;
                             iResult = mkdir(charwholedir, 0600);

                             if (iResult != 0)
                             {
                                std::cout << "gpp deployta, make a new dir falied" << wholedir << std::endl;
                             }
                          }

                          if (stat(charwholedir, &st) == 0)
                          {
                             std::cout << "gpp deloyta: write a new file " << filename << std::endl;

                             std::ofstream outfile;
                             outfile.open(filename, std::ofstream::out | std::ofstream::trunc | std::ofstream::binary);

                             const char *data;
                             data = ta_chunk.buffer().c_str();
                             outfile.write(data, ta_chunk.buffer().length());
                             outfile.close();

                             status_ = FINISH;
                             ta_reply.set_code(0);

                             ta_response.Finish(ta_reply, Status::OK, this);
                          } else
                          {
                             ta_reply.set_code(-3);
                             status_ = FINISH;

                             ta_response.Finish(ta_reply, Status::OK, this);
                          }
                       }

                    }else
                    {
                       std::cout << "gpp receive no deployta jwtsvid or validate jwt failed" << std::endl;
                       ta_reply.set_code(-1);
                       ta_reply.set_flag(flag);
                       status_ = FINISH;

                       ta_response.Finish(ta_reply, Status::OK, this);
                    }

                    break;
                 }

                 case ServerImpl::CallData::SS_TEECC_LiveTransfer:
                 {
                    if(lt_request.requestcode() == 0){
                       sleep(100);
                       status_ = FINISH;
                       lt_reply.set_replycode(0);
                       lt_response.Finish(lt_reply, Status::OK, this);
                    }
                 }

                 default:
                    break;
              }
           } else
           {
              GPR_ASSERT(status_ == FINISH);
              delete this;
              std::cout << std::endl;
           }
        }

    private:
        gpp::AsyncService *service_;
        ServerCompletionQueue *cq_;
        ServerContext ctx_;
        ServiceType s_type_;
        Inicont_Request inicont_request;
        Inicont_Reply inicont_reply;
        ServerAsyncResponseWriter <Inicont_Reply> inicont_response;
        Fincont_Request fincont_request;
        Fincont_Reply fincont_reply;
        ServerAsyncResponseWriter <Fincont_Reply> fincont_response;
        Opes_Request opes_request;
        Opes_Reply opes_reply;
        ServerAsyncResponseWriter <Opes_Reply> opes_response;
        Close_Request close_request;
        Close_Reply close_reply;
        ServerAsyncResponseWriter <Close_Reply> close_response;
        Invo_Request invo_request;
        Invo_Reply invo_reply;
        ServerAsyncResponseWriter <Invo_Reply> invo_response;
        TA_Chunk ta_chunk;
        TA_Reply ta_reply;
        ServerAsyncResponseWriter <TA_Reply> ta_response;
        Setjwt_Request setjwt_request;
        Setjwt_Reply setjwt_reply;
        ServerAsyncResponseWriter <Setjwt_Reply> setjwt_response;
        LT_Request lt_request;
        LT_Reply lt_reply;
        ServerAsyncResponseWriter <LT_Reply> lt_response;

        enum CallStatus
        {
            CREATE, PROCESS, CHECKCANCEL, FINISH
        };
        CallStatus status_;

        pthread_mutex_t *mutex_workerrec_;
        pthread_cond_t *cond_notbusy_;
        wr_t *workerrec_;
        wr_t *ltworkerrec_;
    };

    void RunServer()
    {
       std::string server_address(gpproxy_address);
       grpc::EnableDefaultHealthCheckService(true);
       grpc::reflection::InitProtoReflectionServerBuilderPlugin();

       ServerBuilder builder;
       builder.SetMaxReceiveMessageSize(50 * 1024 * 1024);

       std::cout << "gpproxy server    key  path = " << global_serverkey_path << std::endl;
       std::cout << "gpproxy server    cert path = " << global_servercert_path << std::endl;
       std::cout << "gpproxy client ca cert path = " << global_clientcacert_path << std::endl;

       int igrpctls = grpc_tls;
       switch (igrpctls)
       {
          case 0:
          {
             builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

             break;
          }

          case 1:
          {
             FILE *pipe;
             char buffer[128];
             std::string result;

             std::string strcmd = "openssl rsa -in " + global_serverkey_path + " -out "
                                  + global_serverkey_path + ".nopass";
             std::string nopass_serverkey_path = global_serverkey_path + ".nopass";

             pipe = popen(strcmd.c_str(), "r");
             if (!pipe)
             {
                std::cout << "gpp popen '" << strcmd << "' failed" << std::endl;
                exit(1);
             }
             result = "";
             // read till end of process:
             while (!feof(pipe))
             {
                // use buffer to read and add to result
                if (fgets(buffer, 128, pipe) != NULL)
                   result += buffer;
             }
             pclose(pipe);


             strcmd = "openssl rsa -in " + nopass_serverkey_path + " -check -noout";
             pipe = popen(strcmd.c_str(), "r");
             if (!pipe)
             {
                std::cout << "gpp popen '" << strcmd << "' failed" << std::endl;
                exit(1);
             }
             result = "";
             // read till end of process:
             while (!feof(pipe))
             {
                // use buffer to read and add to result
                if (fgets(buffer, 128, pipe) != NULL)
                   result += buffer;
             }
             pclose(pipe);
             std::string keyok("RSA key ok\n");

             if (result.compare(keyok) != 0)
             {
                std::cout << "gpp '" + global_serverkey_path + "' integrity is broken" << std::endl;
                exit(1);
             }

             std::string sigfile_path = global_strcfgfiletemp + "/.gpp/certs/msg.sig";
             std::string msgfile_path = global_strcfgfiletemp + "/.gpp/certs/msg.txt";
             strcmd =
                   "openssl dgst -sha256 -sign " + nopass_serverkey_path + " -out " + sigfile_path + " " + msgfile_path;
             system(strcmd.c_str());
             // ${_openssl} x509 -in ${CRTPEM} -pubkey -out ${PUBPEM}
             std::string pubkeyfile_path = global_strcfgfiletemp + "/.gpp/certs/server_pubkey.pem";
             strcmd = "openssl x509 -in " + global_servercert_path + " -pubkey -out " + pubkeyfile_path;
             system(strcmd.c_str());

             // ${_openssl} dgst -sha256 -verify ${PUBPEM} -signature msg.sig msg.txt
             strcmd = "openssl dgst -sha256 -verify " + pubkeyfile_path + " -signature " + sigfile_path + " " +
                      msgfile_path;
             // system(strcmd.c_str());
             pipe = popen(strcmd.c_str(), "r");
             if (!pipe)
             {
                std::cout << "gpp popen '" << strcmd << "' failed" << std::endl;
                exit(1);
             }
             result = "";
             // read till end of process:
             while (!feof(pipe))
             {
                // use buffer to read and add to result
                if (fgets(buffer, 128, pipe) != NULL)
                   result += buffer;
             }
             pclose(pipe);
             std::string verifyok("Verified OK\n");
             if (result.compare(verifyok) != 0)
             {
                std::cout << "gpp '" + global_serverkey_path + "' is not matched with '" + global_servercert_path + "'"
                          << std::endl;
                exit(1);
             }

             std::string strdayseconds;
             char *resulttemp;
             const char slash[] = "\n";
             char *parresult;
             std::string strparresult;
             std::string willexpire("Certificate will expire");

             // 7 days in seconds
             strdayseconds = "604800";
             strcmd = "openssl x509 -enddate -noout -in " + global_servercert_path + " -checkend " + strdayseconds;
             pipe = popen(strcmd.c_str(), "r");
             if (!pipe)
             {
                std::cout << "gpp popen '" << strcmd << "' failed" << std::endl;
                exit(1);
             }
             result = "";
             // read till end of process:
             while (!feof(pipe))
             {
                // use buffer to read and add to result
                if (fgets(buffer, 128, pipe) != NULL)
                   result += buffer;
             }
             pclose(pipe);
;
             resulttemp = const_cast<char *>(result.data());
             parresult = strtok(resulttemp, slash);
             while (parresult != NULL)
             {
                strparresult = std::string(parresult);
                parresult = strtok(NULL, slash);
             }
             if (strparresult.compare(willexpire) == 0)
             {
                std::cout << "gpp '" << global_servercert_path << "' will expire in 7 days, please reget it"
                          << std::endl;
                exit(1);
             }

             auto serverkey = get_file_contents(nopass_serverkey_path);
             strcmd = "rm -f " + global_serverkey_path + ".nopass";
             system(strcmd.c_str());
             strcmd = "rm -f " + pubkeyfile_path;
             system(strcmd.c_str());
             strcmd = "rm -f " + sigfile_path;
             system(strcmd.c_str());

             auto servercert = get_file_contents(global_servercert_path);
             grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp = {
                   serverkey.c_str(), servercert.c_str()
             };

             grpc::SslServerCredentialsOptions ssl_opts(GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE);
             ssl_opts.pem_key_cert_pairs.push_back(pkcp);
             std::shared_ptr <grpc::ServerCredentials> creds;
             creds = grpc::SslServerCredentials(ssl_opts);

             builder.AddListeningPort(server_address, creds);

             break;
          }

          case 2:
          {
             FILE *pipe;
             char buffer[128];
             std::string result;

             std::string strcmd = "openssl rsa -in " + global_serverkey_path + " -out "
                                  + global_serverkey_path + ".nopass";
             std::string nopass_serverkey_path = global_serverkey_path + ".nopass";
             system(strcmd.c_str());

             strcmd = "openssl rsa -in " + nopass_serverkey_path + " -check -noout";
             pipe = popen(strcmd.c_str(), "r");
             if (!pipe)
             {
                std::cout << "gpp popen '" << strcmd << "' failed" << std::endl;
                exit(1);
             }
             result = "";
             // read till end of process:
             while (!feof(pipe))
             {
                // use buffer to read and add to result
                if (fgets(buffer, 128, pipe) != NULL)
                   result += buffer;
             }
             pclose(pipe);
             std::string keyok("RSA key ok\n");
             if (result.compare(keyok) != 0)
             {
                std::cout << "gpp '" + global_serverkey_path + "' integrity is broken" << std::endl;
                exit(1);
             }

             std::string sigfile_path = global_strcfgfiletemp + "/.gpp/certs/msg.sig";
             std::string msgfile_path = global_strcfgfiletemp + "/.gpp/certs/msg.txt";
             strcmd =
                   "openssl dgst -sha256 -sign " + nopass_serverkey_path + " -out " + sigfile_path + " " + msgfile_path;
             system(strcmd.c_str());
             // ${_openssl} x509 -in ${CRTPEM} -pubkey -out ${PUBPEM}
             std::string pubkeyfile_path = global_strcfgfiletemp + "/.gpp/certs/server_pubkey.pem";
             strcmd = "openssl x509 -in " + global_servercert_path + " -pubkey -out " + pubkeyfile_path;
             system(strcmd.c_str());

             // ${_openssl} dgst -sha256 -verify ${PUBPEM} -signature msg.sig msg.txt
             strcmd = "openssl dgst -sha256 -verify " + pubkeyfile_path + " -signature " + sigfile_path + " " +
                      msgfile_path;
             // system(strcmd.c_str());
             pipe = popen(strcmd.c_str(), "r");
             if (!pipe)
             {
                std::cout << "gpp popen '" << strcmd << "' failed" << std::endl;
                exit(1);
             }
             result = "";
             // read till end of process:
             while (!feof(pipe))
             {
                // use buffer to read and add to result
                if (fgets(buffer, 128, pipe) != NULL)
                   result += buffer;
             }
             pclose(pipe);
             std::string verifyok("Verified OK\n");
             if (result.compare(verifyok) != 0)
             {
                std::cout << "gpp '" + global_serverkey_path + "' is not matched with '" + global_servercert_path + "'"
                          << std::endl;
                exit(1);
             }

             std::string strdayseconds;
             char *resulttemp;
             const char slash[] = "\n";
             char *parresult;
             std::string strparresult;
             std::string willexpire("Certificate will expire");

             // 7 days in seconds
             strdayseconds = "604800";
             strcmd = "openssl x509 -enddate -noout -in " + global_servercert_path + " -checkend " + strdayseconds;
             // system(strcmd.c_str());
             pipe = popen(strcmd.c_str(), "r");
             if (!pipe)
             {
                std::cout << "gpp popen '" << strcmd << "' failed" << std::endl;
                exit(1);
             }
             result = "";
             // read till end of process:
             while (!feof(pipe))
             {
                // use buffer to read and add to result
                if (fgets(buffer, 128, pipe) != NULL)
                   result += buffer;
             }
             pclose(pipe);

             resulttemp = const_cast<char *>(result.data());
             parresult = strtok(resulttemp, slash);
             while (parresult != NULL)
             {
                strparresult = std::string(parresult);
                parresult = strtok(NULL, slash);
             }
             if (strparresult.compare(willexpire) == 0)
             {
                std::cout << "gpp '" << global_servercert_path << "' will expire in 7 days, please reget it"
                          << std::endl;
                exit(1);
             }

             strdayseconds = "604800";
             strcmd = "openssl x509 -enddate -noout -in " + global_clientcacert_path + " -checkend " + strdayseconds;
             pipe = popen(strcmd.c_str(), "r");
             if (!pipe)
             {
                std::cout << "gpp popen '" << strcmd << "' failed" << std::endl;
                exit(1);
             }
             result = "";
             // read till end of process:
             while (!feof(pipe))
             {
                // use buffer to read and add to result
                if (fgets(buffer, 128, pipe) != NULL)
                   result += buffer;
             }
             pclose(pipe);
             resulttemp = const_cast<char *>(result.data());
             parresult = strtok(resulttemp, slash);
             while (parresult != NULL)
             {
                strparresult = std::string(parresult);
                parresult = strtok(NULL, slash);
             }
             if (strparresult.compare(willexpire) == 0)
             {
                std::cout << "gpp '" << global_clientcacert_path << "' will expire in 7 days, please reget it"
                          << std::endl;
                exit(1);
             }

             auto serverkey = get_file_contents(nopass_serverkey_path);
             strcmd = "rm -f " + global_serverkey_path + ".nopass";
             system(strcmd.c_str());
             strcmd = "rm -f " + pubkeyfile_path;
             system(strcmd.c_str());
             strcmd = "rm -f " + sigfile_path;
             system(strcmd.c_str());

             auto servercert = get_file_contents(global_servercert_path);
             auto clientcacert = get_file_contents(global_clientcacert_path); // for verifying clients
             grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp = {
                   serverkey.c_str(), servercert.c_str()
             };

             grpc::SslServerCredentialsOptions ssl_opts(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
             ssl_opts.pem_root_certs = clientcacert;
             ssl_opts.pem_key_cert_pairs.push_back(pkcp);
             std::shared_ptr <grpc::ServerCredentials> creds;
             creds = grpc::SslServerCredentials(ssl_opts);

             builder.AddListeningPort(server_address, creds);

             break;
          }

          default:
          {
             builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
          }
       }

       // Register "service" as the instance through which we'll communicate with
       // clients. In this case it corresponds to an *synchronous* service.
       builder.RegisterService(&service_);

       for (int i = 0; i < global_max_num_thread; i++)
       {
          cq_.emplace_back(builder.AddCompletionQueue());
       }
       server_ = builder.BuildAndStart();
       //Finally assemble the server.
       std::cout << "gpproxy is listening on " << server_address << std::endl;

       server_threads_.emplace_back(std::thread(
             [this]
             {
                 this->session_timeout_process(&mutex_workerrec, workerrec);
             }
       ));
       server_threads_.emplace_back(std::thread(
             [this]
             {
                 this->context_timeout_process(&mutex_workerrec, &cond_notbusy, workerrec);
             }
       ));

       for (unsigned int i = 0; i < global_max_num_thread; i++)
       {
          server_threads_.emplace_back(std::thread(
                [this, i]
                {
                    this->HandleRpcs(i);
                }));
          std::cout << "thread " << i << " created." << std::endl;
       }
       std::this_thread::sleep_until(std::chrono::time_point<std::chrono::system_clock>::max());
    }

    void HandleRpcs(int i)
    {
       new CallData(&service_,
                    cq_[i].get(),
                    ServerImpl::CallData::SS_TEECC_InitializeContext,
                    &mutex_workerrec,
                    &cond_notbusy,
                    workerrec,
                    ltworkerrec);
       new CallData(&service_,
                    cq_[i].get(),
                    ServerImpl::CallData::SS_TEECC_FinalizeContext,
                    &mutex_workerrec, &cond_notbusy,
                    workerrec,
                    ltworkerrec);
       new CallData(&service_,
                    cq_[i].get(),
                    ServerImpl::CallData::SS_TEECC_OpenSession,
                    &mutex_workerrec,
                    &cond_notbusy,
                    workerrec,
                    ltworkerrec);
       new CallData(&service_,
                    cq_[i].get(),
                    ServerImpl::CallData::SS_TEECC_CloseSession,
                    &mutex_workerrec,
                    &cond_notbusy,
                    workerrec,
                    ltworkerrec);
       new CallData(&service_,
                    cq_[i].get(),
                    ServerImpl::CallData::SS_TEECC_InvokeCommand,
                    &mutex_workerrec,
                    &cond_notbusy,
                    workerrec,
                    ltworkerrec);
       new CallData(&service_,
                    cq_[i].get(),
                    ServerImpl::CallData::SS_TEECC_TA,
                    &mutex_workerrec,
                    &cond_notbusy,
                    workerrec,
                    ltworkerrec);
       new CallData(&service_,
                    cq_[i].get(),
                    ServerImpl::CallData::SS_TEECC_SetJwt,
                    &mutex_workerrec,
                    &cond_notbusy,
                    workerrec,
                    ltworkerrec);

       new CallData(&service_,
                    cq_[i].get(),
                    ServerImpl::CallData::SS_TEECC_LiveTransfer,
                    &mutex_workerrec,
                    &cond_notbusy,
                    workerrec,
                    ltworkerrec);
       void *tag;
       bool ok;

       while (true)
       {
          GPR_ASSERT(cq_[i]->Next(&tag, &ok));
          //std::cout << "gpp thread[" << i << "], cq_[" << i << "]"
                    //<< std::endl;

          static_cast<CallData *>(tag)->Process();
       }
    }

    void
    session_timeout_process(
          pthread_mutex_t *mutex_workerrec,
          wr_t *workerrec
    )
    {
       struct timeval tv;
       uint64_t u64time;

       char workername[1024];
       memset((char *) workername, 0, 1024);
       int iworker;

       uint32_t in_session_seesionid;
       uint32_t in_session_serviceid_timelow = 0;
       uint32_t in_session_serviceid_timemid = 0;
       uint32_t in_session_serviceid_timehiandver = 0;
       uint32_t in_session_serviceid_clockseqandnode_size = 8;
       uint32_t in_session_serviceid_clockseqandnode[8];
       uint32_t in_session_opscnt = 0;
       uint64_t in_session_head_next = 0;
       uint64_t in_session_head_prev = 0;
       uint64_t in_session_context;

       uint32_t seesionid;
       uint32_t serviceid_timelow;
       uint32_t serviceid_timemid;
       uint32_t serviceid_timehiandver;
       uint32_t *serviceid_clockseqandnode;
       int serviceid_clockseqandnode_realsize;
       uint32_t opscnt;
       uint64_t head_next;
       uint64_t head_prev;
       uint64_t session_context;

       sin_t *sinIns;

       while (1)
       {
          sleep(global_timeout_session);

          pthread_mutex_lock(mutex_workerrec);
          for (iworker = 0; iworker < global_max_num_worker; iworker++)
          {
             if (workerrec[iworker].busy == 1)
             {
                printf("close session timeout workerno : %d\n",iworker);
                sinIns = NULL;
                if (workerrec[iworker].first != NULL)
                {
                   sinIns = workerrec[iworker].first;
                   do
                   {
                      gettimeofday(&tv, NULL);
                      u64time = (long unsigned int) (tv.tv_sec -
                                                     sinIns->session_createtime.tv_sec
                      );
                      sin_t *sinTemp = NULL;

                      if (u64time > global_timeout_session)
                      {
                         sprintf(workername, "%s%d", "gpworker", iworker);

                         in_session_seesionid = sinIns->session_id;
                         in_session_context = workerrec[iworker].context_addr;

                         for (int iind = 0; iind < 8; iind++)
                         {
                            in_session_serviceid_clockseqandnode[iind] = 0;
                         }

                         pthread_mutex_unlock(mutex_workerrec);

                         uint32_t serviceid_clockseqandnode_outsize_temp;
                         serviceid_clockseqandnode_realsize = 8;
                         serviceid_clockseqandnode =
                               (uint32_t *) malloc(
                                     serviceid_clockseqandnode_realsize * sizeof(uint32_t)
                               );

                         printf("\ngpp method call teec closesession for timeout process \n");

                         method_call_teec_closesession(
                               workername,

                               in_session_seesionid,
                               in_session_serviceid_timelow,
                               in_session_serviceid_timemid,
                               in_session_serviceid_timehiandver,
                               in_session_serviceid_clockseqandnode,
                               in_session_serviceid_clockseqandnode_size,
                               in_session_opscnt,
                               in_session_head_next,
                               in_session_head_prev,
                               in_session_context,

                               &seesionid,
                               &serviceid_timelow,
                               &serviceid_timemid,
                               &serviceid_timehiandver,
                               serviceid_clockseqandnode,
                               serviceid_clockseqandnode_realsize,
                               &serviceid_clockseqandnode_outsize_temp,
                               &opscnt,
                               &head_next,
                               &head_prev,
                               &session_context
                         );

                         if (serviceid_clockseqandnode != NULL)
                         {
                            free(serviceid_clockseqandnode);
                         }

                         pthread_mutex_lock(mutex_workerrec);

                         sinTemp = sinIns->prev;
                         if (sinTemp != NULL)
                         {
                            sinTemp->next = sinIns->next;
                         }
                         sinTemp = sinIns->next;
                         if (sinTemp != NULL)
                         {
                            sinTemp->prev = sinIns->prev;
                         }
                         if (workerrec[iworker].last == sinIns)
                         {
                            workerrec[iworker].last = sinIns->prev;
                         }
                         if (workerrec[iworker].first == sinIns)
                         {
                            workerrec[iworker].first = sinIns->next;
                         }

                         sinTemp = sinIns;
                         workerrec[iworker].sessionid_count =
                               workerrec[iworker].sessionid_count - 1;

                      } // end of if timedout
                      sinIns = sinIns->next;
                      if (sinTemp != NULL)
                      {
                         free(sinTemp);
                      }
                   } while (sinIns != NULL);

                } // end of the first not null
             } // end of the busy = 1
          } // end of the for iworker
          pthread_mutex_unlock(mutex_workerrec);
       } // end of while 1
       // return NULL;
    }

    void
    context_timeout_process(
          pthread_mutex_t *mutex_workerrec,
          pthread_cond_t *cond_notbusy,
          wr_t *workerrec
    )
    {
       struct timeval tv;
       uint64_t u64time;

       char workername[1024];
       memset((char *) workername, 0, 1024);
       int iworker;

       int32_t in_fd;
       unsigned char *in_ta_path = NULL;
       int32_t in_ta_path_size = 0;
       uint64_t in_session_list_next = 0;
       uint64_t in_session_list_prev = 0;
       uint64_t in_shrd_mem_list_next = 0;
       uint64_t in_shrd_mem_list_prev = 0;
       uint64_t in_share_buffer_buffer = 0;
       int64_t in_share_buffer_buffer_barrier = 0;
       uint64_t in_context_addr;

       int32_t fd;
       unsigned char *ta_path;
       int32_t ta_path_size;
       uint64_t session_list_next;
       uint64_t session_list_prev;
       uint64_t shrd_mem_list_next;
       uint64_t shrd_mem_list_prev;
       uint64_t share_buffer_buffer;
       int64_t share_buffer_buffer_barrier;
       uint32_t context_tapath_outsize;

       while (1)
       {
          sleep(global_timeout_context);

          pthread_mutex_lock(mutex_workerrec);
          for (iworker = 0; iworker < global_max_num_worker; iworker++)
          {
             if (workerrec[iworker].busy == 1)
             {
                sprintf(workername, "%s%d", "gpworker", iworker);
                gettimeofday(&tv, NULL);
                u64time = (long unsigned int) (tv.tv_sec -
                                               workerrec[iworker].context_createtime.tv_sec
                );
                //std::cout << "u64time: " << u64time << " " << "tv.tv_sec " << tv.tv_sec << "workerrec[iworker].context_createtime.tv_sec " <<
                //workerrec[iworker].context_createtime.tv_sec << std::endl;
                if (u64time > global_timeout_context
                    &&
                    workerrec[iworker].sessionid_count == 0
                      )
                {
                   in_fd = workerrec[iworker].context_fd;
                   in_context_addr = workerrec[iworker].context_addr;
                   ta_path = (unsigned char *) malloc(1024 * sizeof(char));
                   ta_path_size = 1024;
                   memset((char *) ta_path, 0, 1024);

                   pthread_mutex_unlock(mutex_workerrec);

                   printf("\ngpp method call teec finalizecontext for timeout process \n");
                   method_call_teec_fincont(
                         workername,

                         in_fd,
                         in_ta_path,
                         in_ta_path_size,
                         in_session_list_next,
                         in_session_list_prev,
                         in_shrd_mem_list_next,
                         in_shrd_mem_list_prev,
                         in_share_buffer_buffer,
                         in_share_buffer_buffer_barrier,
                         in_context_addr,

                         &fd,
                         ta_path,
                         ta_path_size,
                         &session_list_next,
                         &session_list_prev,
                         &shrd_mem_list_next,
                         &shrd_mem_list_prev,
                         &share_buffer_buffer,
                         &share_buffer_buffer_barrier,

                         &context_tapath_outsize
                   );

                   if (ta_path != NULL)
                   {
                      free(ta_path);
                   }

                   pthread_mutex_lock(mutex_workerrec);

                   workerrec[iworker].busy = 0;
                   pthread_cond_signal(cond_notbusy);
                   workerrec[iworker].context_fd = 0;
                   workerrec[iworker].context_addr = 0xffffffff;
                   workerrec[iworker].sessionid_count = 0;
                   sin_t *sinIns;
                   sin_t *sinInsPrev;
                   sinIns = workerrec[iworker].last;
                   if (sinIns != NULL)
                   {
                      for (;;)
                      {
                         sinInsPrev = sinIns->prev;
                         free(sinIns);
                         sinIns = sinInsPrev;
                         if (sinIns == NULL)
                         {
                            break;
                         }
                      }
                   }

                } // end of the if timeed out
             } // end of the if busy = 1
          } // end of the for iworker
          pthread_mutex_unlock(mutex_workerrec);

       } // end of while 1
    }

private:
    std::vector <std::unique_ptr<ServerCompletionQueue>> cq_;
    gpp::AsyncService service_;
    std::unique_ptr <Server> server_;
    std::vector <std::thread> server_threads_;

    pthread_mutex_t mutex_workerrec;
    pthread_cond_t cond_notbusy;
    wr_t *workerrec = new wr_t[global_max_num_worker];
    wr_t *ltworkerrec = new wr_t[global_max_num_worker];
};


int main(int argc, char **argv)
{
   std::cout << "gpproxy glo_config file         = " << global_strcfgfile << std::endl;
   //printf("gpproxy             %d \n",__LINE__);
   check_config();
   ServerImpl server;

   server.RunServer();

   return 0;
}
