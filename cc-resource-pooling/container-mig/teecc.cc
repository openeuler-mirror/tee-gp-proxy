/*
 */

#include <dlfcn.h>
#include <stdio.h>
#include <iostream>
#include <memory>
#include <fstream>
#include <string.h>
#include <stdlib.h>
#include <iomanip>
#include <thread>
#include <sys/time.h>
#include <openssl/sha.h>
#include <dbus/dbus.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/client_context.h>
#include <grpcpp/security/credentials.h>
#include <atomic>
#include "gt.grpc.pb.h"

#include "teecc.h"
#include "teecc/teec_client_api.h"
#include "yaml-cpp/yaml.h"

#ifdef __cplusplus
extern "C" {
#endif

using grpc::Channel;
using grpc::ChannelArguments;
using grpc::experimental::AltsCredentials;
using grpc::experimental::AltsCredentialsOptions;
using grpc::ClientContext;
using grpc::Status;
using grpc::ClientWriter;
using gt::gpp;
using gt::Inicont_Reply;
using gt::Inicont_Request;
using gt::Fincont_Reply;
using gt::Fincont_Request;
using gt::Opes_Reply;
using gt::Opes_Request;
using gt::Invo_Reply;
using gt::Invo_Request;
using gt::Close_Reply;
using gt::Close_Request;
using gt::TA_Chunk;
using gt::TA_Reply;
using gt::LT_Request;
using gt::LT_Reply;

std::atomic_bool stopFlag(false);
int ltFlag = -1;
int ltnum = 0;
int channel_flag = -1;
char glo_token[1024] = "noToken";
pthread_mutex_t mutex_ltnum;
pthread_mutex_t mutex_ltflag;

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


   if (val == NULL || sizeof(val) * 4 < SHA256_LENTH)
   {
      return -1;
   } else
   {
      memset(val, 0, sizeof(val));
      for (int itemp = 0; itemp < SHA256_LENTH; itemp++)
      {
         val[itemp] = SHA256result[itemp];
      }

   }

   return 0;
}


class GppClient
{
public:
    GppClient(std::shared_ptr <Channel> channel)
          : stub_(gpp::NewStub(channel))
    {}

    // Assembles the client's payload,
    // sends it and presents the response back from the server.
    retstru_teec_inicont externc_teec_initializecontext(
          std::uint8_t *name,
          std::size_t name_size
    )
    {
       // Data we are sending to the server.
       Inicont_Request request;
       request.set_name_size(name_size);
       if (name_size > 0)
       {
          std::string name_temp((char *) name);
          request.set_name(name_temp);
       }
       request.set_token(glo_token);

       // Container for the data we expect from the server.
       Inicont_Reply reply;

       ClientContext context;
       retstru_teec_inicont rreply;

       // The actual RPC.
       Status status = stub_->TEECC_InitializeContext(&context, request, &reply);
       retstru_teec_inicont error;

       rreply.teecresult = reply.teecresult();
       rreply.context_fd = reply.context_fd();
       rreply.context_tapath_outsize = reply.context_tapath_outsize();
       if (rreply.context_tapath_outsize > 0)
       {
          rreply.context_tapath = (uint8_t *) malloc((rreply.context_tapath_outsize + 1) * sizeof(uint8_t));;
          reply.context_tapath().copy((char *) rreply.context_tapath, rreply.context_tapath_outsize, 0);
       }
       rreply.context_sessionlist_next = reply.context_sessionlist_next();
       rreply.context_sessionlist_prev = reply.context_sessionlist_prev();
       rreply.context_shrdmemlist_prev = reply.context_shrdmemlist_prev();
       rreply.context_shrdmemlist_next = reply.context_shrdmemlist_next();
       rreply.context_sharebuffer_buffer = reply.context_sharebuffer_buffer();
       rreply.context_sharebuffer_bufferbarrier = reply.context_sharebuffer_bufferbarrier();
       rreply.context_addr = reply.context_addr();
       rreply.flag = reply.flag();
       // Act upon its status.
       if (status.ok())
       {
          return rreply;
       } else
       {
          std::cout << "libteecc initcontext grpc error: " << status.error_code() << ", " << status.error_message()
                    << std::endl;
          return error;
       }
    }

    retstru_teec_fincont externc_teec_finalizecontext(
          std::int32_t in_context_fd,
          std::uint8_t *in_context_tapath,
          std::int32_t in_context_tapath_size,
          std::uint64_t in_context_sessionlist_next,
          std::uint64_t in_context_sessionlist_prev,
          std::uint64_t in_context_shrdmemlist_next,
          std::uint64_t in_context_shrdmemlist_prev,
          std::uint64_t in_context_sharebuffer_buffer,
          std::int64_t in_context_sharebuffer_bufferbarrier,
          std::uint64_t in_context_addr
    )
    {
       // Data we are sending to the server.
       Fincont_Request request;

       request.set_in_context_fd(in_context_fd);
       request.set_in_context_tapath_size(in_context_tapath_size);
       if (in_context_tapath_size > 0)
       {
          std::string in_context_tapath_temp((char *) in_context_tapath);
          request.set_in_context_tapath(in_context_tapath_temp);
       }
       request.set_in_context_sessionlist_next(in_context_sessionlist_next);
       request.set_in_context_sessionlist_prev(in_context_sessionlist_prev);
       request.set_in_context_shrdmemlist_prev(in_context_shrdmemlist_prev);
       request.set_in_context_shrdmemlist_next(in_context_shrdmemlist_next);
       request.set_in_context_sharebuffer_buffer(in_context_sharebuffer_buffer);
       request.set_in_context_sharebuffer_bufferbarrier(in_context_sharebuffer_bufferbarrier);
       request.set_in_context_addr(in_context_addr);
       request.set_token(glo_token);

       //questntainer for the data we expect from the server.
       Fincont_Reply reply;
       ClientContext context;
       retstru_teec_fincont rreply;

       // The actual RPC.
       Status status = stub_->TEECC_FinalizeContext(&context, request, &reply);
       retstru_teec_fincont error;

       rreply.context_fd = reply.context_fd();
       rreply.context_tapath_outsize = reply.context_tapath_outsize();
       if (rreply.context_tapath_outsize > 0)
       {
          rreply.context_tapath = (uint8_t *) malloc((rreply.context_tapath_outsize + 1) * sizeof(uint8_t));;
          reply.context_tapath().copy((char *) rreply.context_tapath, rreply.context_tapath_outsize, 0);
       }
       rreply.context_sessionlist_next = reply.context_sessionlist_next();
       rreply.context_sessionlist_prev = reply.context_sessionlist_prev();
       rreply.context_shrdmemlist_prev = reply.context_shrdmemlist_prev();
       rreply.context_shrdmemlist_next = reply.context_shrdmemlist_next();
       rreply.context_sharebuffer_buffer = reply.context_sharebuffer_buffer();
       rreply.context_sharebuffer_bufferbarrier = reply.context_sharebuffer_bufferbarrier();
       rreply.flag = reply.flag();
       // Act upon its status.
       if (status.ok())
       {
          return rreply;
       } else
       {
          std::cout << "libteecc finalizecontext grpc error: " << status.error_code() << ", " << status.error_message()
                    << std::endl;
          return error;
       }
    }

    retstru_teec_opensession externc_teec_opensession(
          std::int32_t in_context_fd,
          std::uint8_t *in_context_tapath,
          std::int32_t in_context_tapath_size,
          std::uint64_t in_context_sessionlist_next,
          std::uint64_t in_context_sessionlist_prev,
          std::uint64_t in_context_shrdmemlist_next,
          std::uint64_t in_context_shrdmemlist_prev,
          std::uint64_t in_context_sharebuffer_buffer,
          std::int64_t in_context_sharebuffer_bufferbarrier,
          std::uint32_t in_destination_timelow,
          std::uint32_t in_destination_timemid,
          std::uint32_t in_destination_timehiandver,
          std::uint8_t *in_destination_clockseqandnode,
          std::int32_t in_destination_clockseqandnode_size,
          std::uint32_t in_connectionmethod,
          std::uint64_t in_connectiondata,
          std::uint32_t in_operation_started,
          std::uint32_t in_operation_paramtypes,
          std::uint64_t in_operation_param1_tmpref_buffer,
          std::uint32_t in_operation_param1_tmpref_size,
          std::uint64_t in_operation_param1_memref_parent,
          std::uint32_t in_operation_param1_memref_size,
          std::uint32_t in_operation_param1_memref_offset,
          std::uint32_t in_operation_param1_value_a,
          std::uint32_t in_operation_param1_value_b,
          std::int32_t in_operation_param1_ionref_ionsharefd,
          std::uint32_t in_operation_param1_ionref_ionsize,
          std::uint64_t in_operation_param2_tmpref_buffer,
          std::uint32_t in_operation_param2_tmpref_size,
          std::uint64_t in_operation_param2_memref_parent,
          std::uint32_t in_operation_param2_memref_size,
          std::uint32_t in_operation_param2_memref_offset,
          std::uint32_t in_operation_param2_value_a,
          std::uint32_t in_operation_param2_value_b,
          std::int32_t in_operation_param2_ionref_ionsharefd,
          std::uint32_t in_operation_param2_ionref_ionsize,
          std::uint64_t in_operation_param3_tmpref_buffer,
          std::uint32_t in_operation_param3_tmpref_size,
          std::uint64_t in_operation_param3_memref_parent,
          std::uint32_t in_operation_param3_memref_size,
          std::uint32_t in_operation_param3_memref_offset,
          std::uint32_t in_operation_param3_value_a,
          std::uint32_t in_operation_param3_value_b,
          std::int32_t in_operation_param3_ionref_ionsharefd,
          std::uint32_t in_operation_param3_ionref_ionsize,
          std::uint64_t in_operation_param4_tmpref_buffer,
          std::uint32_t in_operation_param4_tmpref_size,
          std::uint64_t in_operation_param4_memref_parent,
          std::uint32_t in_operation_param4_memref_size,
          std::uint32_t in_operation_param4_memref_offset,
          std::uint32_t in_operation_param4_value_a,
          std::uint32_t in_operation_param4_value_b,
          std::int32_t in_operation_param4_ionref_ionsharefd,
          std::uint32_t in_operation_param4_ionref_ionsize,
          std::uint64_t in_operation_session,
          std::int32_t in_operation_cancelflag,
          std::uint32_t in_returnorigin,
          std::uint64_t in_context_addr
    )
    {
       // Data we are sending to the server.
       Opes_Request request;
       request.set_in_context_fd(in_context_fd);
       request.set_in_context_tapath_size(in_context_tapath_size);
       if (in_context_tapath_size > 0)
       {
          std::string in_context_tapath_temp((char *) in_context_tapath);
          request.set_in_context_tapath(in_context_tapath_temp);
       }
       request.set_in_context_sessionlist_next(in_context_sessionlist_next);
       request.set_in_context_sessionlist_prev(in_context_sessionlist_prev);
       request.set_in_context_shrdmemlist_prev(in_context_shrdmemlist_prev);
       request.set_in_context_shrdmemlist_next(in_context_shrdmemlist_next);
       request.set_in_context_sharebuffer_buffer(in_context_sharebuffer_buffer);
       request.set_in_context_sharebuffer_bufferbarrier(in_context_sharebuffer_bufferbarrier);
       request.set_in_destination_timelow(in_destination_timelow);
       request.set_in_destination_timemid(in_destination_timemid);
       request.set_in_destination_timehiandver(in_destination_timehiandver);
       request.set_in_destination_cad_size(in_destination_clockseqandnode_size);
       if (in_destination_clockseqandnode_size > 0)
       {
          for (int i = 0; i < in_destination_clockseqandnode_size; i++)
          {
             request.add_in_destination_clockseqandnode(in_destination_clockseqandnode[i]);
          }

       }
       request.set_in_connectionmethod(in_connectionmethod);
       request.set_in_connectiondata(in_connectiondata);
       request.set_in_operation_started(in_operation_started);
       request.set_in_operation_paramtypes(in_operation_paramtypes);
       request.set_in_operation_param1_tmpref_buffer(in_operation_param1_tmpref_buffer);
       request.set_in_operation_param1_tmpref_size(in_operation_param1_tmpref_size);
       request.set_in_operation_param1_memref_parent(in_operation_param1_memref_parent);
       request.set_in_operation_param1_memref_size(in_operation_param1_memref_size);
       request.set_in_operation_param1_memref_offset(in_operation_param1_memref_offset);
       request.set_in_operation_param1_value_a(in_operation_param1_value_a);
       request.set_in_operation_param1_value_b(in_operation_param1_value_b);
       request.set_in_operation_param1_ionref_ionsharefd(in_operation_param1_ionref_ionsharefd);
       request.set_in_operation_param1_ionref_ionsize(in_operation_param1_ionref_ionsize);
       request.set_in_operation_param2_tmpref_buffer(in_operation_param2_tmpref_buffer);
       request.set_in_operation_param2_tmpref_size(in_operation_param2_tmpref_size);
       request.set_in_operation_param2_memref_parent(in_operation_param2_memref_parent);
       request.set_in_operation_param2_memref_size(in_operation_param2_memref_size);
       request.set_in_operation_param2_memref_offset(in_operation_param2_memref_offset);
       request.set_in_operation_param2_value_a(in_operation_param2_value_a);
       request.set_in_operation_param2_value_b(in_operation_param2_value_b);
       request.set_in_operation_param2_ionref_ionsharefd(in_operation_param2_ionref_ionsharefd);
       request.set_in_operation_param2_ionref_ionsize(in_operation_param2_ionref_ionsize);
       request.set_in_operation_param3_tmpref_buffer(in_operation_param3_tmpref_buffer);
       request.set_in_operation_param3_tmpref_size(in_operation_param3_tmpref_size);
       request.set_in_operation_param3_memref_parent(in_operation_param3_memref_parent);
       request.set_in_operation_param3_memref_size(in_operation_param3_memref_size);
       request.set_in_operation_param3_memref_offset(in_operation_param3_memref_offset);
       request.set_in_operation_param3_value_a(in_operation_param3_value_a);
       request.set_in_operation_param3_value_b(in_operation_param3_value_b);
       request.set_in_operation_param3_ionref_ionsharefd(in_operation_param3_ionref_ionsharefd);
       request.set_in_operation_param3_ionref_ionsize(in_operation_param3_ionref_ionsize);
       request.set_in_operation_param4_tmpref_buffer(in_operation_param4_tmpref_buffer);
       request.set_in_operation_param4_tmpref_size(in_operation_param4_tmpref_size);
       request.set_in_operation_param4_memref_parent(in_operation_param4_memref_parent);
       request.set_in_operation_param4_memref_size(in_operation_param4_memref_size);
       request.set_in_operation_param4_memref_offset(in_operation_param4_memref_offset);
       request.set_in_operation_param4_value_a(in_operation_param4_value_a);
       request.set_in_operation_param4_value_b(in_operation_param4_value_b);
       request.set_in_operation_param4_ionref_ionsharefd(in_operation_param4_ionref_ionsharefd);
       request.set_in_operation_param4_ionref_ionsize(in_operation_param4_ionref_ionsize);
       request.set_in_operation_session(in_operation_session);
       request.set_in_operation_cancelflag(in_operation_cancelflag);
       request.set_in_returnorigin(in_returnorigin);
       request.set_in_context_addr(in_context_addr);

       request.set_token(glo_token);
       //questntainer for the data we expect from the server.
       Opes_Reply reply;
       ClientContext context;
       retstru_teec_opensession rreply;

       // The actual RPC.
       Status status = stub_->TEECC_OpenSession(&context, request, &reply);
       retstru_teec_opensession error;

       rreply.teecresult = reply.teecresult();
       rreply.context_fd = reply.context_fd();
       rreply.context_tapath_outsize = reply.context_tapath_outsize();
       if (rreply.context_tapath_outsize > 0)
       {
          rreply.context_tapath = (uint8_t *) malloc((rreply.context_tapath_outsize + 1) * sizeof(uint8_t));;
          reply.context_tapath().copy((char *) rreply.context_tapath, rreply.context_tapath_outsize, 0);
       }
       rreply.context_sessionlist_next = reply.context_sessionlist_next();
       rreply.context_sessionlist_prev = reply.context_sessionlist_prev();
       rreply.context_shrdmemlist_prev = reply.context_shrdmemlist_prev();
       rreply.context_shrdmemlist_next = reply.context_shrdmemlist_next();
       rreply.context_sharebuffer_buffer = reply.context_sharebuffer_buffer();
       rreply.session_sessionid = reply.session_sessionid();
       rreply.session_serviceid_timelow = reply.session_serviceid_timelow();
       rreply.session_serviceid_timemid = reply.session_serviceid_timemid();
       rreply.session_serviceid_timehiandver = reply.session_serviceid_timehiandver();
       rreply.session_serviceid_clockseqandnode_outsize = reply.session_serviceid_clockseqandnode_outsize();
       if (rreply.session_serviceid_clockseqandnode_outsize > 0)
       {
          rreply.session_serviceid_clockseqandnode = new uint8_t[rreply.session_serviceid_clockseqandnode_outsize];
          for (int i = 0; i < rreply.session_serviceid_clockseqandnode_outsize; i++)
          {
             rreply.session_serviceid_clockseqandnode[i] = reply.session_serviceid_clockseqandnode(i);
          }
       }
       rreply.session_opscnt = reply.session_opscnt();
       rreply.session_head_next = reply.session_head_next();
       rreply.session_head_prev = reply.session_head_prev();
       rreply.session_context = reply.session_context();
       rreply.operation_started = reply.operation_started();
       rreply.operation_paramtypes = reply.operation_paramtypes();
       rreply.operation_param1_tmpref_buffer = reply.operation_param1_tmpref_buffer();
       rreply.operation_param1_tmpref_size = reply.operation_param1_tmpref_size();
       rreply.operation_param1_memref_parent = reply.operation_param1_memref_parent();
       rreply.operation_param1_memref_size = reply.operation_param1_memref_size();
       rreply.operation_param1_memref_offset = reply.operation_param1_memref_offset();
       rreply.operation_param1_value_a = reply.operation_param1_value_a();
       rreply.operation_param1_value_b = reply.operation_param1_value_b();
       rreply.operation_param1_ionref_ionsharefd = reply.operation_param1_ionref_ionsharefd();
       rreply.operation_param1_ionref_ionsize = reply.operation_param1_ionref_ionsize();
       rreply.operation_param2_tmpref_buffer = reply.operation_param2_tmpref_buffer();
       rreply.operation_param2_tmpref_size = reply.operation_param2_tmpref_size();
       rreply.operation_param2_memref_parent = reply.operation_param2_memref_parent();
       rreply.operation_param2_memref_size = reply.operation_param2_memref_size();
       rreply.operation_param2_memref_offset = reply.operation_param2_memref_offset();
       rreply.operation_param2_value_a = reply.operation_param2_value_a();
       rreply.operation_param2_value_b = reply.operation_param2_value_b();
       rreply.operation_param2_ionref_ionsharefd = reply.operation_param2_ionref_ionsharefd();
       rreply.operation_param2_ionref_ionsize = reply.operation_param2_ionref_ionsize();
       rreply.operation_param3_tmpref_buffer = reply.operation_param3_tmpref_buffer();
       rreply.operation_param3_tmpref_size = reply.operation_param3_tmpref_size();
       rreply.operation_param3_memref_parent = reply.operation_param3_memref_parent();
       rreply.operation_param3_memref_size = reply.operation_param3_memref_size();
       rreply.operation_param3_memref_offset = reply.operation_param3_memref_offset();
       rreply.operation_param3_value_a = reply.operation_param3_value_a();
       rreply.operation_param3_value_b = reply.operation_param3_value_b();
       rreply.operation_param3_ionref_ionsharefd = reply.operation_param3_ionref_ionsharefd();
       rreply.operation_param3_ionref_ionsize = reply.operation_param3_ionref_ionsize();
       rreply.operation_param4_tmpref_buffer = reply.operation_param4_tmpref_buffer();
       rreply.operation_param4_tmpref_size = reply.operation_param4_tmpref_size();
       rreply.operation_param4_memref_parent = reply.operation_param4_memref_parent();
       rreply.operation_param4_memref_size = reply.operation_param4_memref_size();
       rreply.operation_param4_memref_offset = reply.operation_param4_memref_offset();
       rreply.operation_param4_value_a = reply.operation_param4_value_a();
       rreply.operation_param4_value_b = reply.operation_param4_value_b();
       rreply.operation_param4_ionref_ionsharefd = reply.operation_param4_ionref_ionsharefd();
       rreply.operation_param4_ionref_ionsize = reply.operation_param4_ionref_ionsize();
       rreply.operation_session = reply.operation_session();
       rreply.operation_cancelflag = reply.operation_cancelflag();
       rreply.returnorigin = reply.returnorigin();
       rreply.flag = reply.flag();

       // Act upon its status.
       if (status.ok())
       {
          return rreply;
       } else
       {
          std::cout << "libteecc opensession grpc error: " << status.error_code() << ", " << status.error_message()
                    << std::endl;
          return error;
       }
    }

    retstru_teec_invokecommand externc_teec_invokecommand(
          std::uint32_t in_session_sessionid,
          std::uint32_t in_session_serviceid_timelow,
          std::uint32_t in_session_serviceid_timemid,
          std::uint32_t in_session_serviceid_timehiandver,
          std::uint8_t *in_session_serviceid_clockseqandnode,
          std::uintptr_t in_session_serviceid_clockseqandnode_size,
          std::uint32_t in_session_opscnt,
          std::uint64_t in_session_head_next,
          std::uint64_t in_session_head_prev,
          std::uint64_t in_session_context,
          std::uint32_t in_commandid,
          std::uint32_t in_operation_started,
          std::uint32_t in_operation_paramtypes,
          std::uint64_t in_operation_param1_tmpref_buffer,
          std::uint32_t in_operation_param1_tmpref_size,
          std::uint64_t in_operation_param1_memref_parent,
          std::uint32_t in_operation_param1_memref_parent_flag,
          std::uint32_t in_operation_param1_memref_size,
          std::uint32_t in_operation_param1_memref_offset,
          std::uint32_t in_operation_param1_value_a,
          std::uint32_t in_operation_param1_value_b,
          std::int32_t in_operation_param1_ionref_ionsharefd,
          std::uint32_t in_operation_param1_ionref_ionsize,
          std::uint64_t in_operation_param2_tmpref_buffer,
          std::uint32_t in_operation_param2_tmpref_size,
          std::uint64_t in_operation_param2_memref_parent,
          std::uint32_t in_operation_param2_memref_parent_flag,
          std::uint32_t in_operation_param2_memref_size,
          std::uint32_t in_operation_param2_memref_offset,
          std::uint32_t in_operation_param2_value_a,
          std::uint32_t in_operation_param2_value_b,
          std::int32_t in_operation_param2_ionref_ionsharefd,
          std::uint32_t in_operation_param2_ionref_ionsize,
          std::uint64_t in_operation_param3_tmpref_buffer,
          std::uint32_t in_operation_param3_tmpref_size,
          std::uint64_t in_operation_param3_memref_parent,
          std::uint32_t in_operation_param3_memref_parent_flag,
          std::uint32_t in_operation_param3_memref_size,
          std::uint32_t in_operation_param3_memref_offset,
          std::uint32_t in_operation_param3_value_a,
          std::uint32_t in_operation_param3_value_b,
          std::int32_t in_operation_param3_ionref_ionsharefd,
          std::uint32_t in_operation_param3_ionref_ionsize,
          std::uint64_t in_operation_param4_tmpref_buffer,
          std::uint32_t in_operation_param4_tmpref_size,
          std::uint64_t in_operation_param4_memref_parent,
          std::uint32_t in_operation_param4_memref_parent_flag,
          std::uint32_t in_operation_param4_memref_size,
          std::uint32_t in_operation_param4_memref_offset,
          std::uint32_t in_operation_param4_value_a,
          std::uint32_t in_operation_param4_value_b,
          std::int32_t in_operation_param4_ionref_ionsharefd,
          std::uint32_t in_operation_param4_ionref_ionsize,
          std::uint64_t in_operation_session,
          std::int32_t in_operation_cancelflag,
          std::uint32_t in_returnorigin,
          std::uint8_t *in_buffer1,
          std::uintptr_t in_buffer1_size,
          std::uint8_t *in_buffer2,
          std::uintptr_t in_buffer2_size,
          std::uint8_t *in_buffer3,
          std::uintptr_t in_buffer3_size,
          std::uint8_t *in_buffer4,
          std::uintptr_t in_buffer4_size
    )
    {
       // Data we are sending to the server.
       Invo_Request request;
       request.set_in_session_sessionid(in_session_sessionid);

       request.set_in_session_serviceid_timelow(in_session_serviceid_timelow);
       request.set_in_session_serviceid_timemid(in_session_serviceid_timemid);
       request.set_in_session_serviceid_timehiandver(in_session_serviceid_timehiandver);
       request.set_in_session_serviceid_cad_size(in_session_serviceid_clockseqandnode_size);
       if (in_session_serviceid_clockseqandnode_size > 0)
       {
          for (int i = 0; i < in_session_serviceid_clockseqandnode_size; i++)
          {
             request.add_in_session_serviceid_clockseqandnode(in_session_serviceid_clockseqandnode[i]);
          }

       }
       request.set_in_session_opscnt(in_session_opscnt);
       request.set_in_session_head_next(in_session_head_next);
       request.set_in_session_head_prev(in_session_head_prev);
       request.set_in_session_context(in_session_context);
       request.set_in_commandid(in_commandid);
       request.set_in_operation_started(in_operation_started);
       request.set_in_operation_paramtypes(in_operation_paramtypes);
       request.set_in_operation_param1_tmpref_buffer(in_operation_param1_tmpref_buffer);
       request.set_in_operation_param1_tmpref_size(in_operation_param1_tmpref_size);
       request.set_in_operation_param1_memref_parent(in_operation_param1_memref_parent);
       request.set_in_operation_param1_memref_parent_flag(in_operation_param1_memref_parent_flag);
       request.set_in_operation_param1_memref_size(in_operation_param1_memref_size);
       request.set_in_operation_param1_memref_offset(in_operation_param1_memref_offset);
       request.set_in_operation_param1_value_a(in_operation_param1_value_a);
       request.set_in_operation_param1_value_b(in_operation_param1_value_b);
       request.set_in_operation_param1_ionref_ionsharefd(in_operation_param1_ionref_ionsharefd);
       request.set_in_operation_param1_ionref_ionsize(in_operation_param1_ionref_ionsize);
       request.set_in_operation_param2_tmpref_buffer(in_operation_param2_tmpref_buffer);
       request.set_in_operation_param2_tmpref_size(in_operation_param2_tmpref_size);
       request.set_in_operation_param2_memref_parent(in_operation_param2_memref_parent);
       request.set_in_operation_param2_memref_parent_flag(in_operation_param2_memref_parent_flag);
       request.set_in_operation_param2_memref_size(in_operation_param2_memref_size);
       request.set_in_operation_param2_memref_offset(in_operation_param2_memref_offset);
       request.set_in_operation_param2_value_a(in_operation_param2_value_a);
       request.set_in_operation_param2_value_b(in_operation_param2_value_b);
       request.set_in_operation_param2_ionref_ionsharefd(in_operation_param2_ionref_ionsharefd);
       request.set_in_operation_param2_ionref_ionsize(in_operation_param2_ionref_ionsize);
       request.set_in_operation_param3_tmpref_buffer(in_operation_param3_tmpref_buffer);
       request.set_in_operation_param3_tmpref_size(in_operation_param3_tmpref_size);
       request.set_in_operation_param3_memref_parent(in_operation_param3_memref_parent);
       request.set_in_operation_param3_memref_parent_flag(in_operation_param3_memref_parent_flag);
       request.set_in_operation_param3_memref_size(in_operation_param3_memref_size);
       request.set_in_operation_param3_memref_offset(in_operation_param3_memref_offset);
       request.set_in_operation_param3_value_a(in_operation_param3_value_a);
       request.set_in_operation_param3_value_b(in_operation_param3_value_b);
       request.set_in_operation_param3_ionref_ionsharefd(in_operation_param3_ionref_ionsharefd);
       request.set_in_operation_param3_ionref_ionsize(in_operation_param3_ionref_ionsize);
       request.set_in_operation_param4_tmpref_buffer(in_operation_param4_tmpref_buffer);
       request.set_in_operation_param4_tmpref_size(in_operation_param4_tmpref_size);
       request.set_in_operation_param4_memref_parent(in_operation_param4_memref_parent);
       request.set_in_operation_param4_memref_parent_flag(in_operation_param4_memref_parent_flag);
       request.set_in_operation_param4_memref_size(in_operation_param4_memref_size);
       request.set_in_operation_param4_memref_offset(in_operation_param4_memref_offset);
       request.set_in_operation_param4_value_a(in_operation_param4_value_a);
       request.set_in_operation_param4_value_b(in_operation_param4_value_b);
       request.set_in_operation_param4_ionref_ionsharefd(in_operation_param4_ionref_ionsharefd);
       request.set_in_operation_param4_ionref_ionsize(in_operation_param4_ionref_ionsize);
       request.set_in_operation_session(in_operation_session);
       request.set_in_operation_cancelflag(in_operation_cancelflag);
       request.set_in_returnorigin(in_returnorigin);
       request.set_in_bufer1_size(in_buffer1_size);
       if (in_buffer1_size > 0)
       {
          for (int i = 0; i < in_buffer1_size; i++)
          {
             request.add_in_buffer1(in_buffer1[i]);
          }
       }
       request.set_in_bufer2_size(in_buffer2_size);
       if (in_buffer2_size > 0)
       {
          for (int i = 0; i < in_buffer2_size; i++)
          {
             request.add_in_buffer2(in_buffer2[i]);
          }
       }
       request.set_in_bufer3_size(in_buffer3_size);
       if (in_buffer3_size > 0)
       {
          for (int i = 0; i < in_buffer3_size; i++)
          {
             request.add_in_buffer3(in_buffer3[i]);
          }
       }
       request.set_in_bufer4_size(in_buffer4_size);
       if (in_buffer4_size > 0)
       {
          for (int i = 0; i < in_buffer4_size; i++)
          {
             request.add_in_buffer4(in_buffer4[i]);
          }
       }
       request.set_token(glo_token);
       request.set_lt_flag(ltFlag);

       pthread_mutex_lock(&mutex_ltnum);
       if(ltnum > 0)
       {
          //printf("ltnum %d \n",ltnum);
          std::cout << "session: " << in_session_sessionid << " live transfer successed"<< std::endl;
          ltnum--;
          if(ltnum == 0){
             ltFlag = -1;
          }
       }
       pthread_mutex_unlock(&mutex_ltnum);

       //发送迁移信号到proxy
       //questntainer for the data we expect from the server.
       Invo_Reply reply;
       ClientContext context;
       retstru_teec_invokecommand rreply;

       // The actual RPC.
       Status status = stub_->TEECC_InvokeCommand(&context, request, &reply);
       retstru_teec_invokecommand error;

       rreply.teecresult = reply.teecresult();
       rreply.session_sessionid = reply.session_sessionid();
       rreply.session_serviceid_timelow = reply.session_serviceid_timelow();
       rreply.session_serviceid_timemid = reply.session_serviceid_timemid();
       rreply.session_serviceid_timehiandver = reply.session_serviceid_timehiandver();
       rreply.session_serviceid_clockseqandnode_outsize = reply.session_serviceid_clockseqandnode_outsize();
       if (rreply.session_serviceid_clockseqandnode_outsize > 0)
       {
          rreply.session_serviceid_clockseqandnode = new uint8_t[rreply.session_serviceid_clockseqandnode_outsize];
          for (int i = 0; i < rreply.session_serviceid_clockseqandnode_outsize; i++)
          {
             rreply.session_serviceid_clockseqandnode[i] = reply.session_serviceid_clockseqandnode(i);
          }
       }
       rreply.session_opscnt = reply.session_opscnt();
       rreply.session_head_next = reply.session_head_next();
       rreply.session_head_prev = reply.session_head_prev();
       rreply.session_context = reply.session_context();
       rreply.operation_started = reply.operation_started();
       rreply.operation_paramtypes = reply.operation_paramtypes();
       rreply.operation_param1_tmpref_buffer = reply.operation_param1_tmpref_buffer();
       rreply.operation_param1_tmpref_size = reply.operation_param1_tmpref_size();
       rreply.operation_param1_memref_parent = reply.operation_param1_memref_parent();
       rreply.operation_param1_memref_parent_flag = reply.operation_param1_memref_parent_flag();
       rreply.operation_param1_memref_size = reply.operation_param1_memref_size();
       rreply.operation_param1_memref_offset = reply.operation_param1_memref_offset();
       rreply.operation_param1_value_a = reply.operation_param1_value_a();
       rreply.operation_param1_value_b = reply.operation_param1_value_b();
       rreply.operation_param1_ionref_ionsharefd = reply.operation_param1_ionref_ionsharefd();
       rreply.operation_param1_ionref_ionsize = reply.operation_param1_ionref_ionsize();

       rreply.operation_param2_tmpref_buffer = reply.operation_param2_tmpref_buffer();
       rreply.operation_param2_tmpref_size = reply.operation_param2_tmpref_size();
       rreply.operation_param2_memref_parent = reply.operation_param2_memref_parent();
       rreply.operation_param2_memref_parent_flag = reply.operation_param2_memref_parent_flag();
       rreply.operation_param2_memref_size = reply.operation_param2_memref_size();
       rreply.operation_param2_memref_offset = reply.operation_param2_memref_offset();
       rreply.operation_param2_value_a = reply.operation_param2_value_a();
       rreply.operation_param2_value_b = reply.operation_param2_value_b();
       rreply.operation_param2_ionref_ionsharefd = reply.operation_param2_ionref_ionsharefd();
       rreply.operation_param2_ionref_ionsize = reply.operation_param2_ionref_ionsize();

       rreply.operation_param3_tmpref_buffer = reply.operation_param3_tmpref_buffer();
       rreply.operation_param3_tmpref_size = reply.operation_param3_tmpref_size();
       rreply.operation_param3_memref_parent = reply.operation_param3_memref_parent();
       rreply.operation_param3_memref_parent_flag = reply.operation_param3_memref_parent_flag();
       rreply.operation_param3_memref_size = reply.operation_param3_memref_size();
       rreply.operation_param3_memref_offset = reply.operation_param3_memref_offset();
       rreply.operation_param3_value_a = reply.operation_param3_value_a();
       rreply.operation_param3_value_b = reply.operation_param3_value_b();
       rreply.operation_param3_ionref_ionsharefd = reply.operation_param3_ionref_ionsharefd();
       rreply.operation_param3_ionref_ionsize = reply.operation_param3_ionref_ionsize();

       rreply.operation_param4_tmpref_buffer = reply.operation_param4_tmpref_buffer();
       rreply.operation_param4_tmpref_size = reply.operation_param4_tmpref_size();
       rreply.operation_param4_memref_parent = reply.operation_param4_memref_parent();
       rreply.operation_param4_memref_parent_flag = reply.operation_param4_memref_parent_flag();
       rreply.operation_param4_memref_size = reply.operation_param4_memref_size();
       rreply.operation_param4_memref_offset = reply.operation_param4_memref_offset();
       rreply.operation_param4_value_a = reply.operation_param4_value_a();
       rreply.operation_param4_value_b = reply.operation_param4_value_b();
       rreply.operation_param4_ionref_ionsharefd = reply.operation_param4_ionref_ionsharefd();
       rreply.operation_param4_ionref_ionsize = reply.operation_param4_ionref_ionsize();

       rreply.operation_session = reply.operation_session();
       rreply.operation_cancelflag = reply.operation_cancelflag();
       rreply.returnorigin = reply.returnorigin();
       rreply.buffer1_outsize = reply.buffer1_outsize();
       if (rreply.buffer1_outsize > 0)
       {
          rreply.buffer1 = new uint8_t[rreply.buffer1_outsize];
          for (int i = 0; i < rreply.buffer1_outsize; i++)
          {
             rreply.buffer1[i] = reply.buffer1(i);
          }
       }
       rreply.buffer2_outsize = reply.buffer2_outsize();
       if (rreply.buffer2_outsize > 0)
       {
          rreply.buffer2 = new uint8_t[rreply.buffer2_outsize];
          for (int i = 0; i < rreply.buffer2_outsize; i++)
          {
             rreply.buffer2[i] = reply.buffer2(i);
          }
       }
       rreply.buffer3_outsize = reply.buffer3_outsize();
       if (rreply.buffer3_outsize > 0)
       {
          rreply.buffer3 = new uint8_t[rreply.buffer3_outsize];
          for (int i = 0; i < rreply.buffer3_outsize; i++)
          {
             rreply.buffer3[i] = reply.buffer3(i);
          }
       }
       rreply.buffer4_outsize = reply.buffer4_outsize();
       if (rreply.buffer4_outsize > 0)
       {
          rreply.buffer4 = new uint8_t[rreply.buffer4_outsize];
          for (int i = 0; i < rreply.buffer4_outsize; i++)
          {
             rreply.buffer4[i] = reply.buffer4(i);
          }
       }
       rreply.flag = reply.flag();
       //rreply.ltflag = ;
       // Act upon its status.
       if (status.ok())
       {
          return rreply;
       }
       /*else if(ltFlag == 0)
       {
          std::cout << " live transfer grpc reload: "<< std::endl;
          return rreply;
       }*/
       else
       {
          std::cout << "libteec invokecommand grpc error: " << status.error_code() << ", " << status.error_message()
                    << std::endl;
          return error;
       }
    }

    retstru_teec_closesession externc_teec_closesession(
          std::uint32_t in_session_sessionid,
          std::uint32_t in_session_serviceid_timelow,
          std::uint32_t in_session_serviceid_timemid,
          std::uint32_t in_session_serviceid_timehiandver,
          std::uint8_t *in_session_serviceid_clockseqandnode,
          std::uintptr_t in_session_serviceid_clockseqandnode_size,
          std::uint32_t in_session_opscnt,
          std::uint64_t in_session_head_next,
          std::uint64_t in_session_head_prev,
          std::uint64_t in_session_context
    )
    {
       Close_Request request;

       request.set_in_session_sessionid(in_session_sessionid);
       request.set_in_session_serviceid_timelow(in_session_serviceid_timelow);
       request.set_in_session_serviceid_timemid(in_session_serviceid_timemid);
       request.set_in_session_serviceid_timehiandver(in_session_serviceid_timehiandver);
       request.set_in_session_serviceid_cad_size(in_session_serviceid_clockseqandnode_size);
       if (in_session_serviceid_clockseqandnode_size > 0)
       {
          for (int i = 0; i < in_session_serviceid_clockseqandnode_size; i++)
          {
             request.add_in_session_serviceid_clockseqandnode(in_session_serviceid_clockseqandnode[i]);
          }
       }
       request.set_in_session_opscnt(in_session_opscnt);
       request.set_in_session_head_next(in_session_head_next);
       request.set_in_session_head_prev(in_session_head_prev);
       request.set_in_session_context(in_session_context);
       request.set_token(glo_token);

       Close_Reply reply;
       ClientContext context;
       retstru_teec_closesession rreply;
       // The actual RPC.
       Status status = stub_->TEECC_CloseSession(&context, request, &reply);
       retstru_teec_closesession error;

       rreply.session_sessionid = reply.session_sessionid();
       rreply.session_serviceid_timelow = reply.session_serviceid_timelow();
       rreply.session_serviceid_timemid = reply.session_serviceid_timemid();
       rreply.session_serviceid_timehiandver = reply.session_serviceid_timehiandver();
       rreply.session_serviceid_clockseqandnode_outsize = reply.session_serviceid_cad_outsize();

       if (rreply.session_serviceid_clockseqandnode_outsize > 0)
       {
          rreply.session_serviceid_clockseqandnode = new uint8_t[rreply.session_serviceid_clockseqandnode_outsize];
          for (int i = 0; i < rreply.session_serviceid_clockseqandnode_outsize; i++)
          {
             rreply.session_serviceid_clockseqandnode[i] = reply.session_serviceid_clockseqandnode(i);
          }
       }

       rreply.session_opscnt = reply.session_opscnt();
       rreply.session_head_next = reply.session_head_next();
       rreply.session_head_prev = reply.session_head_prev();
       rreply.session_context = reply.session_context();
       rreply.flag = reply.flag();

       // Act upon its status.
       if (status.ok())
       {
          return rreply;
       } else
       {
          std::cout << "libteec closesession grpc error: " << status.error_code() << ", " << status.error_message()
                    << std::endl;
          return error;
       }
    }


    int
    Upload(
          std::string infile_path,
          std::string subdir,
          std::string outfile_name
    )
    {
       TA_Chunk chunk;
       TA_Reply stats;
       ClientContext context;
       const char *filename = infile_path.data();
       std::ifstream infile;
       int retcode = 0;

       struct timeval start, end;
       gettimeofday(&start, NULL);

       infile.open(filename, std::ifstream::in | std::ifstream::binary);
       if (!infile)
       {
          return TEEC_INFILE_NOT_FOUND;
       }

       long beginoffset, endoffset;
       beginoffset = infile.tellg();
       infile.seekg(0, std::ios::end);
       endoffset = infile.tellg();
       long filesize = endoffset - beginoffset;
       infile.seekg(0, std::ios::beg);
       char *data = new char[filesize];
       infile.read(data, filesize);

       chunk.set_buffer(data, infile.gcount());

       delete[]data;
       infile.close();

       if (subdir.empty())
       {
          std::string strsubdirdefault("default");
          chunk.set_subdir(strsubdirdefault);
       } else
       {
          bool bResult;
          bResult = utf8_check_is_valid(subdir);
          if (bResult == false)
          {
             return TEEC_FAIL;
          }

          chunk.set_subdir(subdir);
       }

       std::string stroutname;
       std::string infile_path_temp = infile_path;
       if (outfile_name.empty())
       {
          char *filenametemp = const_cast<char *>(infile_path_temp.data());
          const char slash[] = "/";
          char *nametemp = strtok(filenametemp, slash);
          while (nametemp != NULL)
          {
             stroutname = std::string(nametemp);
             nametemp = strtok(NULL, slash);
          }
          chunk.set_name(stroutname);
       } else
       {
          chunk.set_name(outfile_name);
       }

       chunk.set_token(glo_token);

       char sha256[SHA256_LENTH];
       int iRet;
       iRet = get_file_sha256((char *) filename, sha256);
       if (iRet != 0)
       {
          return TEEC_FAIL;
       }

       chunk.set_sha256(sha256, SHA256_LENTH);

       Status status = stub_->TEECC_TA(&context, chunk, &stats);


       if (status.ok())
       {
          retcode = stats.code();

          if (stats.code() == 0)
          {
             retcode = 0;
          } else if (stats.code() == -1)
          {
             std::cout << "libteeccc: deployta jwt validate error" << std::endl;
             retcode = TEEC_ERROR_JWTVALIDATE_FAIL;
          } else
          {
             retcode = TEEC_FAIL;
          }
       } else
       {
          std::cout << "libteec deployta grpc error: " << status.error_code() << ", "
                    << status.error_message() << std::endl;
          retcode = TEEC_FAIL;
       }

       return retcode;
    }

    int
    live_transfer(){
       ClientContext context;
       LT_Request lt_request;
       LT_Reply lt_reply;
       int retcode = -1;
       lt_request.set_requestcode(1);

       Status status = stub_->TEECC_LiveTransfer(&context, lt_request, &lt_reply);

       if (status.ok())
       {
          retcode = lt_reply.replycode();
          if (lt_reply.replycode() == 0)
          {
             retcode = 0;
          } else if (lt_reply.replycode() == -1)
          {
             std::cout << "live_transfer: proxy live_transfer error" << std::endl;
             retcode = TEEC_LIVE_TRANSFER_PROXY_FAIL;
          } else
          {
             retcode = TEEC_FAIL;
          }
       } else
       {
          std::cout << "live_transfer  grpc error: " << status.error_code() << ", "
                    << status.error_message() << std::endl;
          retcode = TEEC_FAIL;
       }

       return retcode;
    }

    // Out of the passed in Channel comes the stub, stored here, our view of the
    // server's exposed services.
    std::unique_ptr <gpp::Stub> stub_;
};

static GppClient *client = NULL;
std::shared_ptr <grpc::Channel> gpp_channel = NULL;


std::string global_strcfgfiletemp = getenv("HOME");
std::string global_strcfgfile = global_strcfgfiletemp + "/.teecc/teecc_config.yaml";
YAML::Node  glo_config = YAML::LoadFile(global_strcfgfile);
std::string global_target_str = glo_config["GPPROXY_ADDRESS"].as<std::string>();
std::string global_servercacert_path = global_strcfgfiletemp + "/.teecc/certs/" + glo_config["NAME_SERVERCA_CERT"].as<std::string>();
std::string global_clientkey_path = global_strcfgfiletemp + "/.teecc/certs/" + glo_config["NAME_CLIENT_KEY"].as<std::string>();
std::string global_clientcert_path = global_strcfgfiletemp + "/.teecc/certs/" + glo_config["NAME_CLIENT_CERT"].as<std::string>();
int grpc_tls = glo_config["GRPC_TLS"].as<int>();


int64_t glob_scontaddr;

bool isFileExists_ifstream(std::string &name)
{
   std::ifstream f(name.c_str());
   return f.good();
}

static std::string get_file_contents(std::string fpath)
{
   std::ifstream finstream(fpath);
   std::string contents;
   contents.assign((std::istreambuf_iterator<char>(finstream)),
                   std::istreambuf_iterator<char>());
   finstream.close();
   return contents;
}

/*void *
reply_methodcall_live_transfer(
      DBusMessage *msg,
      DBusConnection *conn
)
{
   DBusMessage *reply;
   DBusMessageIter args;
   dbus_bool_t bResult;
   dbus_uint32_t retcode = -1;
   dbus_uint32_t serial = 0;
   DBusMessageIter structIter;

   printf("\n");
   printf("Received mechod call live_transfer. \n");
   retcode = 0;
   ltFlag = 0;
   //retcode = client->live_transfer();
   // create a reply from the message
   reply = dbus_message_new_method_return(msg);

   // add the arguments to the reply
   dbus_message_iter_init_append(reply, &args);
   dbus_message_iter_open_container(
         &args,
         DBUS_TYPE_STRUCT,
         NULL,
         &structIter
   );

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &retcode
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory! \n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      return NULL;
   }

   *//*if (retcode == 0)
   {
      unsigned char *charp;
      charp = token;
      bResult =
            dbus_message_iter_append_basic(
                  &structIter,
                  DBUS_TYPE_STRING,
                  &charp
            );
      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory! \n");
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_message_unref(reply);
         dbus_connection_flush(conn);
         return NULL;
      }
   }
   *//*

   dbus_message_iter_close_container(
         &args,
         &structIter
   );

   serial = 100;
   if (!dbus_connection_send(conn, reply, &serial))
   {
      fprintf(stderr, "Out Of Memory! \n");
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      return NULL;
   }

   dbus_message_unref(reply);
   dbus_connection_flush(conn);

   return NULL;
}*/

void
receive_livetransfer_signal(
)
{
   DBusMessage *msg;
   DBusConnection *conn;
   DBusMessageIter args;
   DBusError err;
   int ret;
   dbus_bool_t bResult;
   int sigvalue;
   printf("Dbus server for live transfer is listening ... \n");

   // initialise the error
   dbus_error_init(&err);
   //dbus_threads_init_default();

   // connect to the bus and check for errors
   conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
   // conn = dbus_bus_get_private(DBUS_BUS_SESSION, &err);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "Connection Error (%s)\n", err.message);
      dbus_error_free(&err);
      exit(1);
   }
   if (NULL == conn)
   {
      fprintf(stderr, "Connection Null. \n");
      exit(1);
   }

   char dbusname[1024];
   memset((char *) dbusname, 0, 1024);
   // sprintf(dbusname, "%s.method.server", argv[1]);
   sprintf(dbusname, "%s.signal.sink", "live_transfer");
   // request our name on the bus and check for errors
   ret =
         dbus_bus_request_name(
               conn,
               dbusname,
               DBUS_NAME_FLAG_ALLOW_REPLACEMENT,
               &err);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "Name Error (%s)\n", err.message);
      dbus_error_free(&err);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      exit(1);
   }
/*   if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret)
   {
      fprintf(stderr, "Not  Owner (%d)\n", ret);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      exit(1);
   }*/

   dbus_bus_add_match(conn, "type='signal',interface='live_transfer.signal.Type'", &err);
   dbus_connection_flush(conn);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "Match Error (%s)\n", err.message);
      exit(1);
   }
   while (!stopFlag)
   {
      // non blocking read of the next available message
      dbus_connection_read_write(conn, 0);
      msg = dbus_connection_pop_message(conn);

      // loop again if we haven't got a message
      if (NULL == msg)
      {
         usleep(10000);
         continue;
      }

      // check this is a method call for the right interface & method
/*      bResult = dbus_message_is_method_call(
            msg,
            dbusname,
            "live_transfer"
      );
      if (bResult == TRUE)
      {
         reply_methodcall_live_transfer(
               msg,
               conn
         );
      }*/
      if (dbus_message_is_signal(msg, "live_transfer.signal.Type", "live_transfer"))
      {
         // read the parameters
         if (!dbus_message_iter_init(msg, &args))
            fprintf(stderr, "Message Has No Parameters\n");
         else if (DBUS_TYPE_INT32 != dbus_message_iter_get_arg_type(&args))
            fprintf(stderr, "Argument is not int!\n");
         else
            dbus_message_iter_get_basic(&args, &sigvalue);

         printf("Got Signal with value %d\n", sigvalue);
         ltFlag = sigvalue;
      }
      // free the message
      dbus_message_unref(msg);

   } // end of the while true
   printf("Dbus server for live transfer stop\n");

} // end of the function

TEEC_Result
TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
   pthread_mutex_init(&mutex_ltnum, NULL);
   pthread_mutex_init(&mutex_ltflag, NULL);
   if (gpp_channel == NULL)
   {
      int igrpctls = grpc_tls;

      if (grpc_tls != 0 && grpc_tls != 1 && grpc_tls != 2)
      {
         std::cout << global_strcfgfile << " grpc_tls should be 0 or 1 or 2 " << std::endl;
         return TEEC_FAIL;
      }

      switch (igrpctls)
      {
         case 0:
         {
            gpp_channel = grpc::CreateChannel(global_target_str, grpc::InsecureChannelCredentials());
            break;
         }

         case 1:
         {
            if (!isFileExists_ifstream(global_servercacert_path))
            {
               std::cout << "error file : " << global_servercacert_path << " is not exist " << std::endl;
               return TEEC_FAIL;
            }

            std::string strcmd;
            FILE *pipe;
            char buffer[128];
            std::string result;

            std::string strdayseconds;
            char *resulttemp;
            const char slash[] = "\n";
            char *parresult;
            std::string strparresult;
            std::string willexpire("Certificate will expire");

            // 7 days in seconds
            strdayseconds = "604800";
            strcmd = "openssl x509 -enddate -noout -in " + global_servercacert_path + " -checkend " + strdayseconds;
            // system(strcmd.c_str());
            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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
               std::cout << "gpp '" << global_servercacert_path << "' will expire in 7 days, please reget it" << std::endl;
               return TEEC_FAIL;
            }

            auto servercacert = get_file_contents(global_servercacert_path);
            grpc::SslCredentialsOptions ssl_opts;
            ssl_opts.pem_root_certs = servercacert;
            std::shared_ptr <grpc::ChannelCredentials> creds = grpc::SslCredentials(ssl_opts);
            gpp_channel = grpc::CreateChannel(global_target_str, creds);

            break;
         }

         case 2:
         {
            if (!isFileExists_ifstream(global_servercacert_path))
            {
               std::cout << "error file : " << global_servercacert_path << " is not exist " << std::endl;
               return TEEC_FAIL;
            }
            if (!isFileExists_ifstream(global_clientkey_path))
            {
               std::cout << "error file : " << global_clientkey_path << " is not exist " << std::endl;
               return TEEC_FAIL;
            }
            if (!isFileExists_ifstream(global_clientcert_path))
            {
               std::cout << "error file : " << global_clientcert_path << " is not exist " << std::endl;
               return TEEC_FAIL;
            }

            std::string strcmd;
            FILE *pipe;
            char buffer[128];
            std::string result;

            std::string strdayseconds;
            char *resulttemp;
            const char slash[] = "\n";
            char *parresult;
            std::string strparresult;
            std::string willexpire("Certificate will expire");

            // 7 days in seconds
            strdayseconds = "604800";
            strcmd = "openssl x509 -enddate -noout -in " + global_servercacert_path + " -checkend " + strdayseconds;
            // system(strcmd.c_str());
            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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
               std::cout << "libteecc '" << global_servercacert_path << "' will expire in 7 days, please reget it"
                         << std::endl;
               return TEEC_FAIL;
            }

            // 7 days in seconds
            strdayseconds = "604800";
            strcmd = "openssl x509 -enddate -noout -in " + global_clientcert_path + " -checkend " + strdayseconds;
            // system(strcmd.c_str());
            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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
               std::cout << "libteecc '" << global_clientcert_path << "' will expire in 7 days, please reget it" << std::endl;
               return TEEC_FAIL;
            }

            strcmd = "openssl rsa -in " + global_clientkey_path + " -out "
                     + global_clientkey_path + ".nopass";
            std::string nopass_clientkey_path = global_clientkey_path + ".nopass";
            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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

            strcmd = "openssl rsa -in " + nopass_clientkey_path + " -check -noout";
            // system(strcmd.c_str());
            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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
               std::cout << "libteecc '" + global_clientkey_path + "' integrity is broken" << std::endl;
               return TEEC_FAIL;
            }

            std::string sigfile_path = global_strcfgfiletemp + "/.teecc/certs/msg.sig";
            std::string msgfile_path = global_strcfgfiletemp + "/.teecc/certs/msg.txt";
            strcmd =
                  "openssl dgst -sha256 -sign " + nopass_clientkey_path + " -out " + sigfile_path + " " + msgfile_path;
            system(strcmd.c_str());
            // ${_openssl} x509 -in ${CRTPEM} -pubkey -out ${PUBPEM}
            std::string pubkeyfile_path = global_strcfgfiletemp + "/.teecc/certs/client_pubkey.pem";
            strcmd = "openssl x509 -in " + global_clientcert_path + " -pubkey -out " + pubkeyfile_path;
            system(strcmd.c_str());

            // ${_openssl} dgst -sha256 -verify ${PUBPEM} -signature msg.sig msg.txt
            strcmd = "openssl dgst -sha256 -verify " + pubkeyfile_path + " -signature " + sigfile_path + " " +
                     msgfile_path;
            // system(strcmd.c_str());
            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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
            // std::cout << "gpp popen " << strcmd << " succed, result: " << result <<std::endl;
            std::string verifyok("Verified OK\n");
            // std::cout << "result: " << result << std::endl;
            if (result.compare(verifyok) != 0)
            {
               std::cout << "libteecc '" + global_clientkey_path + "' is not matched with '" + global_clientcert_path + "'"
                         << std::endl;
               return TEEC_FAIL;
            }

            auto clientkey = get_file_contents(nopass_clientkey_path);
            strcmd = "rm -f " + global_clientkey_path + ".nopass";
            system(strcmd.c_str());
            strcmd = "rm -f " + pubkeyfile_path;
            system(strcmd.c_str());
            strcmd = "rm -f " + sigfile_path;
            system(strcmd.c_str());

            auto servercacert = get_file_contents(global_servercacert_path);
            // auto clientkey = get_file_contents(global_clientkey_path);
            auto clientcert = get_file_contents(global_clientcert_path);
            grpc::SslCredentialsOptions ssl_opts;
            ssl_opts.pem_root_certs = servercacert;
            ssl_opts.pem_private_key = clientkey;
            ssl_opts.pem_cert_chain = clientcert;
            std::shared_ptr <grpc::ChannelCredentials> creds = grpc::SslCredentials(ssl_opts);
            gpp_channel = grpc::CreateChannel(global_target_str, creds);

            break;
         }

         default:
         {
            gpp_channel = grpc::CreateChannel(global_target_str, grpc::InsecureChannelCredentials());
         }
      }

      client = new GppClient(
            gpp_channel
      );
   }

   std::uint8_t *name_temp = NULL;
   std::uint32_t name_size;
   struct retstru_teec_inicont rs_inicont_ins;

   if (name != NULL)
   {
      name_temp = (uint8_t *) name;
      name_size = strlen(name);
   } else
   {
      name_size = 0;
   }

   if (context == NULL)
   {
      return TEEC_ERROR_BAD_PARAMETERS;
   }
   rs_inicont_ins = client->externc_teec_initializecontext(name_temp,
                                                           name_size
   );

   std::thread live_transfer(receive_livetransfer_signal);
   live_transfer.detach();

   if (rs_inicont_ins.flag == 1)
   {
      std::cout << "libteecc: inicont token null" << std::endl;

      return TEEC_ERROR_BAD_PARAMETERS;
   }
   if (rs_inicont_ins.flag == 2)
   {
      std::cout << "libteecc: inicont jwt validate error" << std::endl;
      return TEEC_ERROR_BAD_PARAMETERS;
   }

   if (rs_inicont_ins.teecresult == TEEC_SUCCESS)
   {
      context->fd = rs_inicont_ins.context_fd;

      if (
            rs_inicont_ins.context_tapath_outsize > 0 &&
            rs_inicont_ins.context_tapath != NULL
            )
      {
         if (context->ta_path == NULL)
         {
            return TEEC_ERROR_CONTEXT_TAPATH_NULL;
         } else
         {
            memcpy(
                  context->ta_path,
                  rs_inicont_ins.context_tapath,
                  rs_inicont_ins.context_tapath_outsize
            );
            *(context->ta_path + rs_inicont_ins.context_tapath_outsize) = 0;
         }
      } else
      {
         context->ta_path = NULL;
      }
      context->session_list.next = (struct ListNode *) rs_inicont_ins.context_sessionlist_next;
      context->session_list.prev = (struct ListNode *) rs_inicont_ins.context_sessionlist_prev;
      context->shrd_mem_list.next = (struct ListNode *) rs_inicont_ins.context_shrdmemlist_next;
      context->shrd_mem_list.prev = (struct ListNode *) rs_inicont_ins.context_shrdmemlist_prev;
      context->share_buffer.buffer = (void *) rs_inicont_ins.context_sharebuffer_buffer;
      context->share_buffer.buffer_barrier.__align = rs_inicont_ins.context_sharebuffer_bufferbarrier;
      glob_scontaddr = rs_inicont_ins.context_addr;
   }
   return static_cast<TEEC_Result>(rs_inicont_ins.teecresult);
}

void
TEEC_FinalizeContext(TEEC_Context *context)
{
   std::int32_t in_context_fd;
   std::uint8_t *in_context_tapath;
   std::int32_t in_context_tapath_size;
   std::uint64_t in_context_sessionlist_next;
   std::uint64_t in_context_sessionlist_prev;
   std::uint64_t in_context_shrdmemlist_next;
   std::uint64_t in_context_shrdmemlist_prev;
   std::uint64_t in_context_sharebuffer_buffer;
   std::int64_t in_context_sharebuffer_bufferbarrier;
   struct retstru_teec_fincont rs_fincont_ins;


   if (gpp_channel == NULL)
   {
      std::cout << "libteecc: the grpc client or channel is null, when executing TEEC_FinalizeContext." << std::endl;
      return;
   }

   if (context == NULL)
   {
      return;
   }

   in_context_fd = context->fd;
   in_context_tapath = context->ta_path;
   if (in_context_tapath == NULL)
   {
      in_context_tapath_size = 0;
   } else
   {
      std::string strtmp((char *) in_context_tapath);
      bool bResult;
      bResult = utf8_check_is_valid(strtmp);
      if (bResult == true)
      {
         in_context_tapath_size = strtmp.length();
      } else
      {
         in_context_tapath_size = 0;
      }
   }
   in_context_sessionlist_next = (uint64_t) context->session_list.next;
   in_context_sessionlist_prev = (uint64_t) context->session_list.prev;
   in_context_shrdmemlist_next = (uint64_t) context->shrd_mem_list.next;
   in_context_shrdmemlist_prev = (uint64_t) context->shrd_mem_list.prev;
   in_context_sharebuffer_buffer = (uint64_t) context->share_buffer.buffer;
   in_context_sharebuffer_bufferbarrier = context->share_buffer.buffer_barrier.__align;

   rs_fincont_ins = client->externc_teec_finalizecontext(in_context_fd,
                                                         in_context_tapath,
                                                         in_context_tapath_size,
                                                         in_context_sessionlist_next,
                                                         in_context_sessionlist_prev,
                                                         in_context_shrdmemlist_next,
                                                         in_context_shrdmemlist_prev,
                                                         in_context_sharebuffer_buffer,
                                                         in_context_sharebuffer_bufferbarrier,
                                                         glob_scontaddr);
   if (rs_fincont_ins.flag == 1)
   {
      std::cout << "libteecc: fincont token null" << std::endl;
      return;
   }
   if (rs_fincont_ins.flag == 2)
   {
      std::cout << "libteecc: fincont jwt validate error" << std::endl;
      return;
   }
#if 0
   std::cout << "externc_teec_finalizecontext: " << std::endl;
   std::cout << "gpp reply   context_fd: " << rs_fincont_ins.context_fd <<std::endl;
   std::cout << "gpp reply   context_tapath_outsize: " <<std::dec<< rs_fincont_ins.context_tapath_outsize <<std::endl;
   if( rs_fincont_ins.context_tapath_outsize > 0){
       std::cout << "gpp reply   context_tapath: " << rs_fincont_ins.context_tapath <<std::endl;
   }
   std::cout << "gpp reply   context_sessionlist_next: 0x " << std::hex << std::setfill('0') << std::setw(16) <<rs_fincont_ins.context_sessionlist_next <<std::endl;
   std::cout << "gpp reply   context_sessionlist_prev: 0x " << std::hex << std::setfill('0') << std::setw(16) <<rs_fincont_ins.context_sessionlist_prev <<std::endl;
   std::cout << "gpp reply   context_shrdmemlist_next: 0x " << std::hex << std::setfill('0') << std::setw(16) <<rs_fincont_ins.context_shrdmemlist_next <<std::endl;
   std::cout << "gpp reply   context_shrdmemlist_prev: 0x " << std::hex << std::setfill('0') << std::setw(16) <<rs_fincont_ins.context_shrdmemlist_prev <<std::endl;
   std::cout << "gpp reply   context_sharebuffer_buffer: 0x " << std::hex << std::setfill('0') << std::setw(16) <<rs_fincont_ins.context_sharebuffer_buffer <<std::endl;
   std::cout << "gpp reply   context_sharebuffer_bufferbarrier: 0x " << std::hex << std::setfill('0') << std::setw(16) <<rs_fincont_ins.context_sharebuffer_bufferbarrier <<std::endl;
#endif
   context->fd = rs_fincont_ins.context_fd;
   if (
         rs_fincont_ins.context_tapath_outsize > 0 &&
         rs_fincont_ins.context_tapath != NULL
         )
   {
      if (context->ta_path == NULL)
      {
         return;
      }
   }
   context->session_list.next = (struct ListNode *) rs_fincont_ins.context_sessionlist_next;
   context->session_list.prev = (struct ListNode *) rs_fincont_ins.context_sessionlist_prev;
   context->shrd_mem_list.next = (struct ListNode *) rs_fincont_ins.context_shrdmemlist_next;
   context->shrd_mem_list.prev = (struct ListNode *) rs_fincont_ins.context_shrdmemlist_prev;
   context->share_buffer.buffer = (void *) rs_fincont_ins.context_sharebuffer_buffer;
   context->share_buffer.buffer_barrier.__align = rs_fincont_ins.context_sharebuffer_bufferbarrier;

   stopFlag = true;

   gpp_channel.reset();
   delete gpp_channel.get();
   delete client;
}

TEEC_Result
TEEC_OpenSession(TEEC_Context *context,
                 TEEC_Session *session,
                 const TEEC_UUID *destination,
                 uint32_t connectionMethod,
                 const void *connectionData,
                 TEEC_Operation *operation,
                 uint32_t *returnOrigin
)
{

   std::int32_t in_context_fd;
   std::uint8_t *in_context_tapath;
   std::int32_t in_context_tapath_size;
   std::uint64_t in_context_sessionlist_next;
   std::uint64_t in_context_sessionlist_prev;
   std::uint64_t in_context_shrdmemlist_next;
   std::uint64_t in_context_shrdmemlist_prev;
   std::uint64_t in_context_sharebuffer_buffer;
   std::int64_t in_context_sharebuffer_bufferbarrier;

   if (gpp_channel == NULL)
   {
      std::cout << "libteecc: the grpc client or channel is null, when executing TEEC_OpenSession." << std::endl;
      return TEEC_ERROR_GRPC_ERROR;
   }

   if (context == NULL)
   {
      return TEEC_ERROR_BAD_PARAMETERS;
   }

   if (session == NULL)
   {
      return TEEC_ERROR_BAD_PARAMETERS;
   }

   if (destination == NULL)
   {
      return TEEC_ERROR_BAD_PARAMETERS;
   }

   in_context_fd = context->fd;
   in_context_tapath = context->ta_path;

   if (in_context_tapath == NULL)
   {
      in_context_tapath_size = 0;
   } else
   {
      in_context_tapath_size = strlen((const char *) in_context_tapath);
   }
   in_context_sessionlist_next = (uint64_t) context->session_list.next;
   in_context_sessionlist_prev = (uint64_t) context->session_list.prev;
   in_context_shrdmemlist_next = (uint64_t) context->shrd_mem_list.next;
   in_context_shrdmemlist_prev = (uint64_t) context->shrd_mem_list.prev;
   in_context_sharebuffer_buffer = (uint64_t) context->share_buffer.buffer;
   in_context_sharebuffer_bufferbarrier = context->share_buffer.buffer_barrier.__align;

   uint32_t in_destination_timelow;
   uint32_t in_destination_timemid;
   uint32_t in_destination_timehiandver;
   uint8_t in_destination_clockseqandnode[8];
   int32_t in_destination_clockseqandnode_size;

   uint32_t in_connectionmethod;
   uint64_t in_connectiondata;

   uint32_t in_operation_started;
   uint32_t in_operation_paramtypes;

   uint64_t in_operation_param1_tmpref_buffer;
   uint32_t in_operation_param1_tmpref_size;
   uint64_t in_operation_param1_memref_parent;
   uint32_t in_operation_param1_memref_size;
   uint32_t in_operation_param1_memref_offset;
   uint32_t in_operation_param1_value_a;
   uint32_t in_operation_param1_value_b;
   int32_t in_operation_param1_ionref_ionsharefd;
   uint32_t in_operation_param1_ionref_ionsize;

   uint64_t in_operation_param2_tmpref_buffer;
   uint32_t in_operation_param2_tmpref_size;
   uint64_t in_operation_param2_memref_parent;
   uint32_t in_operation_param2_memref_size;
   uint32_t in_operation_param2_memref_offset;
   uint32_t in_operation_param2_value_a;
   uint32_t in_operation_param2_value_b;
   int32_t in_operation_param2_ionref_ionsharefd;
   uint32_t in_operation_param2_ionref_ionsize;

   uint64_t in_operation_param3_tmpref_buffer;
   uint32_t in_operation_param3_tmpref_size;
   uint64_t in_operation_param3_memref_parent;
   uint32_t in_operation_param3_memref_size;
   uint32_t in_operation_param3_memref_offset;
   uint32_t in_operation_param3_value_a;
   uint32_t in_operation_param3_value_b;
   int32_t in_operation_param3_ionref_ionsharefd;
   uint32_t in_operation_param3_ionref_ionsize;

   uint64_t in_operation_param4_tmpref_buffer;
   uint32_t in_operation_param4_tmpref_size;
   uint64_t in_operation_param4_memref_parent;
   uint32_t in_operation_param4_memref_size;
   uint32_t in_operation_param4_memref_offset;
   uint32_t in_operation_param4_value_a;
   uint32_t in_operation_param4_value_b;
   int32_t in_operation_param4_ionref_ionsharefd;
   uint32_t in_operation_param4_ionref_ionsize;

   uint64_t in_operation_session;
   int32_t in_operation_cancelflag;

   uint32_t in_returnorigin;

   struct retstru_teec_opensession rs_opensession_ins;


   in_destination_timelow = destination->timeLow;
   in_destination_timemid = destination->timeMid;
   in_destination_timehiandver = destination->timeHiAndVersion;
   for (int i = 0; i < 8; i++)
   {
      in_destination_clockseqandnode[i] = destination->clockSeqAndNode[i];
   }
   in_destination_clockseqandnode_size = 8;

   in_connectionmethod = connectionMethod;
   in_connectiondata = (uint64_t) connectionData;

   in_operation_started = operation->started;
   in_operation_paramtypes = operation->paramTypes;

   in_operation_param1_tmpref_buffer = (uint64_t) operation->params[0].tmpref.buffer;
   in_operation_param1_tmpref_size = operation->params[0].tmpref.size;
   in_operation_param1_memref_parent = (uint64_t) operation->params[0].memref.parent;
   in_operation_param1_memref_size = operation->params[0].memref.size;
   in_operation_param1_memref_offset = operation->params[0].memref.offset;
   in_operation_param1_value_a = operation->params[0].value.a;
   in_operation_param1_value_b = operation->params[0].value.b;
   in_operation_param1_ionref_ionsharefd = operation->params[0].ionref.ion_share_fd;
   in_operation_param1_ionref_ionsize = operation->params[0].ionref.ion_size;

   in_operation_param2_tmpref_buffer = (uint64_t) operation->params[1].tmpref.buffer;
   in_operation_param2_tmpref_size = operation->params[1].tmpref.size;
   in_operation_param2_memref_parent = (uint64_t) operation->params[1].memref.parent;
   in_operation_param2_memref_size = operation->params[1].memref.size;
   in_operation_param2_memref_offset = operation->params[1].memref.offset;
   in_operation_param2_value_a = operation->params[1].value.a;
   in_operation_param2_value_b = operation->params[1].value.b;
   in_operation_param2_ionref_ionsharefd = operation->params[1].ionref.ion_share_fd;
   in_operation_param2_ionref_ionsize = operation->params[1].ionref.ion_size;

   in_operation_param3_tmpref_buffer = (uint64_t) operation->params[2].tmpref.buffer;
   in_operation_param3_tmpref_size = operation->params[2].tmpref.size;
   in_operation_param3_memref_parent = (uint64_t) operation->params[2].memref.parent;
   in_operation_param3_memref_size = operation->params[2].memref.size;
   in_operation_param3_memref_offset = operation->params[2].memref.offset;
   in_operation_param3_value_a = operation->params[2].value.a;
   in_operation_param3_value_b = operation->params[2].value.b;
   in_operation_param3_ionref_ionsharefd = operation->params[2].ionref.ion_share_fd;
   in_operation_param3_ionref_ionsize = operation->params[2].ionref.ion_size;

   in_operation_param4_tmpref_buffer = (uint64_t) operation->params[3].tmpref.buffer;
   in_operation_param4_tmpref_size = operation->params[3].tmpref.size;
   in_operation_param4_memref_parent = (uint64_t) operation->params[3].memref.parent;
   in_operation_param4_memref_size = operation->params[3].memref.size;
   in_operation_param4_memref_offset = operation->params[3].memref.offset;
   in_operation_param4_value_a = operation->params[3].value.a;
   in_operation_param4_value_b = operation->params[3].value.b;
   in_operation_param4_ionref_ionsharefd = operation->params[3].ionref.ion_share_fd;
   in_operation_param4_ionref_ionsize = operation->params[3].ionref.ion_size;

   in_operation_session = (uint64_t) operation->session;
   in_operation_cancelflag = operation->cancel_flag;

   in_returnorigin = *returnOrigin;

   rs_opensession_ins =
         client->externc_teec_opensession(
               in_context_fd,
               in_context_tapath,
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
               glob_scontaddr
         );
   if (rs_opensession_ins.flag == 1)
   {
      std::cout << "libteecc: opensession token null" << std::endl;
      return TEEC_ERROR_BAD_PARAMETERS;
   }
   if (rs_opensession_ins.flag == 2)
   {
      std::cout << "libteecc: opensession jwt validate error" << std::endl;
      return TEEC_ERROR_BAD_PARAMETERS;
   }

#if 0
   std::cout << "externc_teec_opensession:" << std::endl;
   std::cout << "gpp request in_context_fd: 0x " << std::hex << std::setfill('0') << std::setw(8) << in_context_fd
             << std::endl;
   std::cout << "gpp request in_context_addr: 0x" << std::hex << std::setfill('0') << std::setw(8)
             << (unsigned long) glob_scontaddr << std::endl;
   std::cout << "gpp reply   teecresult: " << std::hex << std::setfill('0') << std::setw(8)
             << rs_opensession_ins.teecresult << std::endl;
   std::cout << "gpp reply   context_fd: " << std::hex << std::setfill('0') << std::setw(8)
             << rs_opensession_ins.context_fd << std::endl;

   if (
           rs_opensession_ins.context_tapath_outsize > 0
           &&
           rs_opensession_ins.context_tapath != NULL
      )
   {
       std::cout << "gpp reply   context_tapath: " << rs_opensession_ins.context_tapath << std::endl;
   }
   printf("gpp reply   context_tapath outsize             = %ld\n",
          rs_opensession_ins.context_tapath_outsize);
#endif

#if 0
   printf("ret context_sessionlist_next           = 0x %16.16lx\n",
          rs_opensession_ins.context_sessionlist_next);
   printf("ret context_sessionlist_prev           = 0x %16.16lx\n",
          rs_opensession_ins.context_sessionlist_prev);
   printf("ret context_shrdmemlist_next           = 0x %16.16lx\n",
          rs_opensession_ins.context_shrdmemlist_next);
   printf("ret context_shrdmemlist_prev           = 0x %16.16lx\n",
          rs_opensession_ins.context_shrdmemlist_prev);
   printf("ret context_sharebuffer_buffer         = 0x %16.16lx\n",
          rs_opensession_ins.context_sharebuffer_buffer);
   printf("ret context_sharebuffer_bufferbarrier  = 0x %16.16lx\n",
          (long unsigned int) rs_opensession_ins.context_sharebuffer_bufferbarrier);
#endif

#if 0
   std::cout << "gpp reply   session_sessionid: 0x " << std::hex << std::setfill('0') << std::setw(8)
             << rs_opensession_ins.session_sessionid << std::endl;
#endif

#if 0
   printf("ret session_serviceid_timelow          = 0x %8.8x\n",
          rs_opensession_ins.session_serviceid_timelow);
   printf("ret session_serviceid_timemid          = 0x %8.8x\n",
          rs_opensession_ins.session_serviceid_timemid);
   printf("ret session_serviceid_timehiandver     = 0x %8.8x\n",
          rs_opensession_ins.session_serviceid_timehiandver);
   if (
           rs_opensession_ins.session_serviceid_clockseqandnode_outsize > 0
           &&
           rs_opensession_ins.session_serviceid_clockseqandnode != NULL
           ) {
       printf("ret session_serviceid_clockseqandnode  = \n");
       for (uintptr_t uisize = 0;
            uisize < rs_opensession_ins.session_serviceid_clockseqandnode_outsize;
            uisize++) {
           printf(" %2.2x", *(rs_opensession_ins.session_serviceid_clockseqandnode + uisize));
       }
       printf("\n");
   } else {
       printf("ret            clockseqandnode addr    = 0x %16.16lx\n",
              (unsigned long) rs_opensession_ins.session_serviceid_clockseqandnode);
   }
   printf("ret            clockseqandnode_outsize = %ld\n",
          rs_opensession_ins.session_serviceid_clockseqandnode_outsize);
   printf("ret session_opscnt                     = 0x %8.8x\n",
          rs_opensession_ins.session_opscnt);
   printf("ret session_head_next                  = 0x %16.16lx\n",
          rs_opensession_ins.session_head_next);
   printf("ret session_head_prev                  = 0x %16.16lx\n",
          rs_opensession_ins.session_head_prev);
#endif

#if 0
   std::cout << "gpp reply   session_context: 0x " << std::hex << std::setfill('0') << std::setw(16)
             << rs_opensession_ins.session_context << std::endl;
#endif
   if (rs_opensession_ins.teecresult == TEEC_SUCCESS)
   {
      context->fd = rs_opensession_ins.context_fd;

      if (
            rs_opensession_ins.context_tapath_outsize > 0 &&
            rs_opensession_ins.context_tapath != NULL
            )
      {
         if (context->ta_path == NULL)
         {
            return TEEC_ERROR_CONTEXT_TAPATH_NULL;
         }
      }
      context->session_list.next = (struct ListNode *) rs_opensession_ins.context_sessionlist_next;
      context->session_list.prev = (struct ListNode *) rs_opensession_ins.context_sessionlist_prev;
      context->shrd_mem_list.next = (struct ListNode *) rs_opensession_ins.context_shrdmemlist_next;
      context->shrd_mem_list.prev = (struct ListNode *) rs_opensession_ins.context_shrdmemlist_prev;
      context->share_buffer.buffer = (void *) rs_opensession_ins.context_sharebuffer_buffer;
      context->share_buffer.buffer_barrier.__align = rs_opensession_ins.context_sharebuffer_bufferbarrier;

      session->session_id = rs_opensession_ins.session_sessionid;
      session->service_id.timeLow = rs_opensession_ins.session_serviceid_timelow;
      session->service_id.timeMid = rs_opensession_ins.session_serviceid_timemid;
      session->service_id.timeHiAndVersion = rs_opensession_ins.session_serviceid_timehiandver;

      if (rs_opensession_ins.session_serviceid_clockseqandnode_outsize <= 8 &&
          rs_opensession_ins.session_serviceid_clockseqandnode_outsize > 0 &&
          rs_opensession_ins.session_serviceid_clockseqandnode != NULL &&
          session->service_id.clockSeqAndNode != NULL
            )
      {
         for (int i = 0; i < rs_opensession_ins.session_serviceid_clockseqandnode_outsize; i++)
         {
            session->service_id.clockSeqAndNode[i] =
                  (uint8_t)(rs_opensession_ins.session_serviceid_clockseqandnode[i] & 0x000000ff);
         }
      } else
      {
         for (int i = 0; i < 8; i++)
         {
            session->service_id.clockSeqAndNode[i] = 0;
         }
      }
      session->ops_cnt = rs_opensession_ins.session_opscnt;
      session->head.next = (struct ListNode *) rs_opensession_ins.session_head_next;
      session->head.prev = (struct ListNode *) rs_opensession_ins.session_head_prev;
      session->context = (TEEC_Context *) rs_opensession_ins.session_context;


      operation->started = rs_opensession_ins.operation_started;
      operation->paramTypes = rs_opensession_ins.operation_paramtypes;

#if 0
      uint32_t * buffer1_temp = NULL;
      if (
          (rs_opensession_ins.operation_paramtypes & 0x000000ff) == TEEC_MEMREF_TEMP_OUTPUT  ||
          (rs_opensession_ins.operation_paramtypes & 0x000000ff) == TEEC_MEMREF_TEMP_INOUT
         )
      {
         if (operation->params[0].tmpref.buffer == NULL)
         {
            externc_retstru_teec_opensession_free(rs_opensession_ins);
            return TEEC_ERROR_PARAM0_TEMPMEM_NULL;
         }
      }
#endif

      operation->params[0].tmpref.buffer = (void *) rs_opensession_ins.operation_param1_tmpref_buffer;
      operation->params[0].tmpref.size = rs_opensession_ins.operation_param1_tmpref_size;
      operation->params[0].memref.parent =
            (TEEC_SharedMemory *) rs_opensession_ins.operation_param1_memref_parent;
      operation->params[0].memref.size = rs_opensession_ins.operation_param1_memref_size;
      operation->params[0].memref.offset = rs_opensession_ins.operation_param1_memref_offset;
      operation->params[0].value.a = rs_opensession_ins.operation_param1_value_a;
      operation->params[0].value.b = rs_opensession_ins.operation_param1_value_b;
      operation->params[0].ionref.ion_share_fd = rs_opensession_ins.operation_param1_ionref_ionsharefd;
      operation->params[0].ionref.ion_size = rs_opensession_ins.operation_param1_ionref_ionsize;

      operation->params[1].tmpref.buffer = (void *) rs_opensession_ins.operation_param2_tmpref_buffer;
      operation->params[1].tmpref.size = rs_opensession_ins.operation_param2_tmpref_size;
      operation->params[1].memref.parent =
            (TEEC_SharedMemory *) rs_opensession_ins.operation_param2_memref_parent;
      operation->params[1].memref.size = rs_opensession_ins.operation_param2_memref_size;
      operation->params[1].memref.offset = rs_opensession_ins.operation_param2_memref_offset;
      operation->params[1].value.a = rs_opensession_ins.operation_param2_value_a;
      operation->params[1].value.b = rs_opensession_ins.operation_param2_value_b;
      operation->params[1].ionref.ion_share_fd = rs_opensession_ins.operation_param2_ionref_ionsharefd;
      operation->params[1].ionref.ion_size = rs_opensession_ins.operation_param2_ionref_ionsize;

      operation->params[2].tmpref.buffer = (void *) rs_opensession_ins.operation_param3_tmpref_buffer;
      operation->params[2].tmpref.size = rs_opensession_ins.operation_param3_tmpref_size;
      operation->params[2].memref.parent =
            (TEEC_SharedMemory *) rs_opensession_ins.operation_param3_memref_parent;
      operation->params[2].memref.size = rs_opensession_ins.operation_param3_memref_size;
      operation->params[2].memref.offset = rs_opensession_ins.operation_param3_memref_offset;
      operation->params[2].value.a = rs_opensession_ins.operation_param3_value_a;
      operation->params[2].value.b = rs_opensession_ins.operation_param3_value_b;
      operation->params[2].ionref.ion_share_fd = rs_opensession_ins.operation_param3_ionref_ionsharefd;
      operation->params[2].ionref.ion_size = rs_opensession_ins.operation_param3_ionref_ionsize;

      operation->params[3].tmpref.buffer = (void *) rs_opensession_ins.operation_param4_tmpref_buffer;
      operation->params[3].tmpref.size = rs_opensession_ins.operation_param4_tmpref_size;
      operation->params[3].memref.parent =
            (TEEC_SharedMemory *) rs_opensession_ins.operation_param4_memref_parent;
      operation->params[3].memref.size = rs_opensession_ins.operation_param4_memref_size;
      operation->params[3].memref.offset = rs_opensession_ins.operation_param4_memref_offset;
      operation->params[3].value.a = rs_opensession_ins.operation_param4_value_a;
      operation->params[3].value.b = rs_opensession_ins.operation_param4_value_b;
      operation->params[3].ionref.ion_share_fd = rs_opensession_ins.operation_param4_ionref_ionsharefd;
      operation->params[3].ionref.ion_size = rs_opensession_ins.operation_param4_ionref_ionsize;

      operation->session = (TEEC_Session *) rs_opensession_ins.operation_session;
      operation->cancel_flag = rs_opensession_ins.operation_cancelflag;

      *returnOrigin = in_returnorigin;
   }
   return static_cast<TEEC_Result>(rs_opensession_ins.teecresult);
}

extern
TEEC_Result
TEEC_InvokeCommand(TEEC_Session *session,
                   uint32_t commandID,
                   TEEC_Operation *operation,
                   uint32_t *returnOrigin
)
{
   uint32_t in_session_sessionid;
   uint32_t in_session_serviceid_timelow;
   uint32_t in_session_serviceid_timemid;
   uint32_t in_session_serviceid_timehiandver;
   uint8_t in_session_serviceid_clockseqandnode[8];
   uintptr_t in_session_serviceid_clockseqandnode_size;
   uint32_t in_session_opscnt;
   uint64_t in_session_head_next;
   int64_t in_session_head_prev;
   uint64_t in_session_context;

   uint32_t in_commandid;

   uint32_t in_operation_started;
   uint32_t in_operation_paramtypes;

   uint64_t in_operation_param1_tmpref_buffer;
   uint32_t in_operation_param1_tmpref_size;
   uint64_t in_operation_param1_memref_parent;
   uint32_t in_operation_param1_memref_parent_flag;
   uint32_t in_operation_param1_memref_size;
   uint32_t in_operation_param1_memref_offset;
   uint32_t in_operation_param1_value_a;
   uint32_t in_operation_param1_value_b;
   int32_t in_operation_param1_ionref_ionsharefd;
   uint32_t in_operation_param1_ionref_ionsize;

   uint64_t in_operation_param2_tmpref_buffer;
   uint32_t in_operation_param2_tmpref_size;
   uint64_t in_operation_param2_memref_parent;
   uint32_t in_operation_param2_memref_parent_flag;
   uint32_t in_operation_param2_memref_size;
   uint32_t in_operation_param2_memref_offset;
   uint32_t in_operation_param2_value_a;
   uint32_t in_operation_param2_value_b;
   int32_t in_operation_param2_ionref_ionsharefd;
   uint32_t in_operation_param2_ionref_ionsize;

   uint64_t in_operation_param3_tmpref_buffer;
   uint32_t in_operation_param3_tmpref_size;
   uint64_t in_operation_param3_memref_parent;
   uint32_t in_operation_param3_memref_parent_flag;
   uint32_t in_operation_param3_memref_size;
   uint32_t in_operation_param3_memref_offset;
   uint32_t in_operation_param3_value_a;
   uint32_t in_operation_param3_value_b;
   int32_t in_operation_param3_ionref_ionsharefd;
   uint32_t in_operation_param3_ionref_ionsize;

   uint64_t in_operation_param4_tmpref_buffer;
   uint32_t in_operation_param4_tmpref_size;
   uint64_t in_operation_param4_memref_parent;
   uint32_t in_operation_param4_memref_parent_flag;
   uint32_t in_operation_param4_memref_size;
   uint32_t in_operation_param4_memref_offset;
   uint32_t in_operation_param4_value_a;
   uint32_t in_operation_param4_value_b;
   int32_t in_operation_param4_ionref_ionsharefd;
   uint32_t in_operation_param4_ionref_ionsize;

   uint64_t in_operation_session;
   int32_t in_operation_cancelflag;

   uint32_t in_returnorigin;

   struct retstru_teec_invokecommand rs_invokecommand_ins;

   pthread_mutex_lock(&mutex_ltflag);
   if (ltFlag == 1 && channel_flag != 1) {
      struct timeval start, end;
      gettimeofday(&start, NULL);
      gpp_channel.reset();
      int igrpctls = grpc_tls;

      if (grpc_tls != 0 && grpc_tls != 1 && grpc_tls != 2)
      {
         std::cout << global_strcfgfile << " grpc_tls should be 0 or 1 or 2 " << std::endl;
         return TEEC_FAIL;
      }

      switch (igrpctls)
      {
         case 0:
         {
            gpp_channel = grpc::CreateChannel(global_target_str, grpc::InsecureChannelCredentials());
            break;
         }

         case 1:
         {
            if (!isFileExists_ifstream(global_servercacert_path))
            {
               std::cout << "error file : " << global_servercacert_path << " is not exist " << std::endl;
               return TEEC_FAIL;
            }

            std::string strcmd;
            FILE *pipe;
            char buffer[128];
            std::string result;

            std::string strdayseconds;
            char *resulttemp;
            const char slash[] = "\n";
            char *parresult;
            std::string strparresult;
            std::string willexpire("Certificate will expire");

            // 7 days in seconds
            strdayseconds = "604800";
            strcmd = "openssl x509 -enddate -noout -in " + global_servercacert_path + " -checkend " + strdayseconds;
            // system(strcmd.c_str());
            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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
               std::cout << "gpp '" << global_servercacert_path << "' will expire in 7 days, please reget it" << std::endl;
               return TEEC_FAIL;
            }

            auto servercacert = get_file_contents(global_servercacert_path);
            grpc::SslCredentialsOptions ssl_opts;
            ssl_opts.pem_root_certs = servercacert;
            std::shared_ptr <grpc::ChannelCredentials> creds = grpc::SslCredentials(ssl_opts);
            gpp_channel = grpc::CreateChannel(global_target_str, creds);

            break;
         }

         case 2:
         {
            if (!isFileExists_ifstream(global_servercacert_path))
            {
               std::cout << "error file : " << global_servercacert_path << " is not exist " << std::endl;
               return TEEC_FAIL;
            }
            if (!isFileExists_ifstream(global_clientkey_path))
            {
               std::cout << "error file : " << global_clientkey_path << " is not exist " << std::endl;
               return TEEC_FAIL;
            }
            if (!isFileExists_ifstream(global_clientcert_path))
            {
               std::cout << "error file : " << global_clientcert_path << " is not exist " << std::endl;
               return TEEC_FAIL;
            }

            std::string strcmd;
            FILE *pipe;
            char buffer[128];
            std::string result;

            std::string strdayseconds;
            char *resulttemp;
            const char slash[] = "\n";
            char *parresult;
            std::string strparresult;
            std::string willexpire("Certificate will expire");

            // 7 days in seconds
            strdayseconds = "604800";
            strcmd = "openssl x509 -enddate -noout -in " + global_servercacert_path + " -checkend " + strdayseconds;
            // system(strcmd.c_str());
            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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
               std::cout << "libteecc '" << global_servercacert_path << "' will expire in 7 days, please reget it"
                         << std::endl;
               return TEEC_FAIL;
            }

            // 7 days in seconds
            strdayseconds = "604800";
            strcmd = "openssl x509 -enddate -noout -in " + global_clientcert_path + " -checkend " + strdayseconds;
            // system(strcmd.c_str());
            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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
               std::cout << "libteecc '" << global_clientcert_path << "' will expire in 7 days, please reget it" << std::endl;
               return TEEC_FAIL;
            }

            strcmd = "openssl rsa -in " + global_clientkey_path + " -out "
                     + global_clientkey_path + ".nopass";
            std::string nopass_clientkey_path = global_clientkey_path + ".nopass";
            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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

            strcmd = "openssl rsa -in " + nopass_clientkey_path + " -check -noout";
            // system(strcmd.c_str());
            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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
               std::cout << "libteecc '" + global_clientkey_path + "' integrity is broken" << std::endl;
               return TEEC_FAIL;
            }

            std::string sigfile_path = global_strcfgfiletemp + "/.teecc/certs/msg.sig";
            std::string msgfile_path = global_strcfgfiletemp + "/.teecc/certs/msg.txt";
            strcmd =
                  "openssl dgst -sha256 -sign " + nopass_clientkey_path + " -out " + sigfile_path + " " + msgfile_path;
            system(strcmd.c_str());
            // ${_openssl} x509 -in ${CRTPEM} -pubkey -out ${PUBPEM}
            std::string pubkeyfile_path = global_strcfgfiletemp + "/.teecc/certs/client_pubkey.pem";
            strcmd = "openssl x509 -in " + global_clientcert_path + " -pubkey -out " + pubkeyfile_path;
            system(strcmd.c_str());

            // ${_openssl} dgst -sha256 -verify ${PUBPEM} -signature msg.sig msg.txt
            strcmd = "openssl dgst -sha256 -verify " + pubkeyfile_path + " -signature " + sigfile_path + " " +
                     msgfile_path;
            // system(strcmd.c_str());
            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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
            // std::cout << "gpp popen " << strcmd << " succed, result: " << result <<std::endl;
            std::string verifyok("Verified OK\n");
            // std::cout << "result: " << result << std::endl;
            if (result.compare(verifyok) != 0)
            {
               std::cout << "libteecc '" + global_clientkey_path + "' is not matched with '" + global_clientcert_path + "'"
                         << std::endl;
               return TEEC_FAIL;
            }

            auto clientkey = get_file_contents(nopass_clientkey_path);
            strcmd = "rm -f " + global_clientkey_path + ".nopass";
            system(strcmd.c_str());
            strcmd = "rm -f " + pubkeyfile_path;
            system(strcmd.c_str());
            strcmd = "rm -f " + sigfile_path;
            system(strcmd.c_str());

            auto servercacert = get_file_contents(global_servercacert_path);
            // auto clientkey = get_file_contents(global_clientkey_path);
            auto clientcert = get_file_contents(global_clientcert_path);
            grpc::SslCredentialsOptions ssl_opts;
            ssl_opts.pem_root_certs = servercacert;
            ssl_opts.pem_private_key = clientkey;
            ssl_opts.pem_cert_chain = clientcert;
            std::shared_ptr <grpc::ChannelCredentials> creds = grpc::SslCredentials(ssl_opts);
            gpp_channel = grpc::CreateChannel(global_target_str, creds);

            break;
         }

         default:
         {
            gpp_channel = grpc::CreateChannel(global_target_str, grpc::InsecureChannelCredentials());
         }
      }
      client = new GppClient(
            gpp_channel
      );
      channel_flag = 1;
      gettimeofday(&end, NULL);
      uint32_t cost = 0;
      cost += (1000000 * end.tv_sec + end.tv_usec) - (1000000 * start.tv_sec + start.tv_usec);
      printf(" grpc reload executed cost time: %ld us \n", cost);

      //std::cout << "session: " << in_session_sessionid << " live transfer successed"<< std::endl;
   }
   pthread_mutex_unlock(&mutex_ltflag);

   if (gpp_channel == NULL)
   {
      std::cout << "libteecc: the grpc client or channel is null, when executing TEEC_InvokeCommand." << std::endl;
      return TEEC_ERROR_GRPC_ERROR;
   }

   if (session == NULL)
   {
      return TEEC_ERROR_BAD_PARAMETERS;
   }

   if (operation == NULL)
   {
      return TEEC_ERROR_BAD_PARAMETERS;
   }

   in_session_sessionid = session->session_id;
   in_session_serviceid_timelow = session->service_id.timeLow;
   in_session_serviceid_timemid = session->service_id.timeMid;
   in_session_serviceid_timehiandver = session->service_id.timeHiAndVersion;
   if (
         session->service_id.clockSeqAndNode != NULL
         )
   {
      for (int i = 0; i < 8; i++)
      {
         in_session_serviceid_clockseqandnode[i] =
               session->service_id.clockSeqAndNode[i];
      }
   } else
   {
      for (int i = 0; i < 8; i++)
      {
         in_session_serviceid_clockseqandnode[i] = 0;
      }
   }
   in_session_serviceid_clockseqandnode_size = 8;
   in_session_opscnt = session->ops_cnt;
   in_session_head_next = (uint64_t) session->head.next;
   in_session_head_prev = (uint64_t) session->head.prev;
   in_session_context = glob_scontaddr;

   in_commandid = commandID;

   in_operation_started = operation->started;
   in_operation_paramtypes = operation->paramTypes;

   in_operation_param1_ionref_ionsharefd = operation->params[0].ionref.ion_share_fd;
   in_operation_param1_ionref_ionsize = operation->params[0].ionref.ion_size;

   in_operation_param2_ionref_ionsharefd = operation->params[1].ionref.ion_share_fd;
   in_operation_param2_ionref_ionsize = operation->params[1].ionref.ion_size;

   in_operation_param3_ionref_ionsharefd = operation->params[2].ionref.ion_share_fd;
   in_operation_param3_ionref_ionsize = operation->params[2].ionref.ion_size;

   in_operation_param4_ionref_ionsharefd = operation->params[3].ionref.ion_share_fd;
   in_operation_param4_ionref_ionsize = operation->params[3].ionref.ion_size;

   uint8_t *in_buffer1 = NULL;
   uintptr_t in_buffer1_size = 0;

   switch (
         TEEC_PARAM_TYPE_GET(operation->paramTypes, 0)
         )
   {
      case TEEC_VALUE_INPUT:
      case TEEC_VALUE_INOUT:
      {
         in_operation_param1_value_a = operation->params[0].value.a;
         in_operation_param1_value_b = operation->params[0].value.b;

         break;
      }
      case TEEC_MEMREF_TEMP_INPUT:
      case TEEC_MEMREF_TEMP_INOUT:
      {
         if (
               operation->params[0].tmpref.buffer == NULL
               )
         {
            return TEEC_ERROR_PARAM0_TEMPMEM_NULL;
         }
         if (
               operation->params[0].tmpref.size <= 0
               )
         {
            return TEEC_ERROR_PARAM0_TEMPMEM_LESS;
         }

         in_operation_param1_tmpref_buffer = (uint64_t) operation->params[0].tmpref.buffer;
         in_operation_param1_tmpref_size = operation->params[0].tmpref.size;

         in_buffer1_size = operation->params[0].tmpref.size;
         in_buffer1 = (uint8_t *) malloc(in_buffer1_size * sizeof(uint8_t));
         for (int isize = 0; isize < in_buffer1_size; isize++)
         {
            in_buffer1[isize] = (uint8_t) * ((uint8_t * )(operation->params[0].tmpref.buffer) + isize);
         }

         break;
      }

      case TEEC_MEMREF_TEMP_OUTPUT:
      {
         if (
               operation->params[0].tmpref.buffer == NULL
               )
         {
            return TEEC_ERROR_PARAM0_TEMPMEM_NULL;
         }
         if (
               operation->params[0].tmpref.size <= 0
               )
         {
            return TEEC_ERROR_PARAM0_TEMPMEM_LESS;
         }

         in_operation_param1_tmpref_buffer = (uint64_t) operation->params[0].tmpref.buffer;
         in_operation_param1_tmpref_size = operation->params[0].tmpref.size;


         break;
      }


      case TEEC_MEMREF_WHOLE:
      {
         switch (operation->params[0].memref.parent->flags)
         {
            case TEEC_MEM_INPUT:
            case TEEC_MEM_INOUT:
            {
               if (
                     operation->params[0].memref.parent->buffer == NULL ||
                     operation->params[0].memref.parent->ops_cnt != 0xfffe
                     )
               {
                  return TEEC_ERROR_PARAM0_MEMREF_NULL;
               }
               if (
                     operation->params[0].memref.parent->size <= 0
                     )
               {
                  return TEEC_ERROR_PARAM0_MEMREF_LESS;
               }

               in_operation_param1_memref_parent =
                     (uint64_t) operation->params[0].memref.parent->buffer;
               in_operation_param1_memref_parent_flag =
                     (uint32_t) operation->params[0].memref.parent->flags;
               in_operation_param1_memref_size = operation->params[0].memref.size;

               in_buffer1_size = operation->params[0].memref.parent->size;
               in_buffer1 = (uint8_t *) malloc(in_buffer1_size * sizeof(uint8_t));
               for (int isize = 0; isize < in_buffer1_size; isize++)
               {
                  in_buffer1[isize] =
                        (uint8_t) * ((uint8_t * )(
                              operation->params[0].memref.parent->buffer
                        )
                                     + isize
                        );
               }

               break;
            }

            case TEEC_MEM_OUTPUT:
            {
               if (
                     operation->params[0].memref.parent->buffer == NULL ||
                     operation->params[0].memref.parent->ops_cnt != 0xfffe
                     )
               {
                  return TEEC_ERROR_PARAM0_MEMREF_NULL;
               }
               if (
                     operation->params[0].memref.parent->size <= 0
                     )
               {
                  return TEEC_ERROR_PARAM0_MEMREF_LESS;
               }

               in_operation_param1_memref_parent =
                     (uint64_t) operation->params[0].memref.parent->buffer;
               in_operation_param1_memref_parent_flag =
                     (uint32_t) operation->params[0].memref.parent->flags;
               in_operation_param1_memref_size = operation->params[0].memref.size;

               break;
            }

            default:
            {
               return TEEC_ERROR_NO_SHAREMEMFLAG;
               break;
            }

         } // end of switch(operation->params[0].memref.parent->flags)

         break;
      }
         // end of case TEEC_MEMREF_WHOLE


      case TEEC_MEMREF_PARTIAL_INPUT:
      case TEEC_MEMREF_PARTIAL_INOUT:
      {
         if (operation->params[0].memref.parent->buffer == NULL)
         {
            return TEEC_ERROR_PARAM0_MEMREF_NULL;
         }
         if (operation->params[0].memref.parent->size <= 0)
         {
            return TEEC_ERROR_PARAM0_MEMREF_LESS;
         }

         in_operation_param1_memref_parent =
               (uint64_t) operation->params[0].memref.parent->buffer;
         in_operation_param1_memref_parent_flag =
               (uint32_t) operation->params[0].memref.parent->flags;
         in_operation_param1_memref_offset = operation->params[0].memref.offset;
         in_operation_param1_memref_size = operation->params[0].memref.size;

         in_buffer1_size = operation->params[0].memref.parent->size;
         in_buffer1 = (uint8_t *) malloc(in_buffer1_size * sizeof(uint8_t));
         for (int isize = 0; isize < in_buffer1_size; isize++)
         {
            in_buffer1[isize] =
                  (uint8_t) * ((uint8_t * )(operation->params[0].memref.parent->buffer) + isize);
         }

         break;
      }
         // end of case TEEC_MEMREF_PARTIAL_INPUT INOUT


      case TEEC_MEMREF_PARTIAL_OUTPUT:
      {
         if (operation->params[0].memref.parent->buffer == NULL)
         {
            return TEEC_ERROR_PARAM0_MEMREF_NULL;
         }
         if (operation->params[0].memref.parent->size <= 0)
         {
            return TEEC_ERROR_PARAM0_MEMREF_LESS;
         }

         in_operation_param1_memref_parent =
               (uint64_t) operation->params[0].memref.parent->buffer;
         in_operation_param1_memref_parent_flag =
               (uint32_t) operation->params[0].memref.parent->flags;
         in_operation_param1_memref_offset = operation->params[0].memref.offset;
         in_operation_param1_memref_size = operation->params[0].memref.size;

         in_buffer1_size = operation->params[0].memref.parent->size;
         in_buffer1 = (uint8_t *) malloc(in_buffer1_size * sizeof(uint8_t));
         for (int isize = 0; isize < in_buffer1_size; isize++)
         {
            in_buffer1[isize] = 0x0;
         }


         break;
      }
         // end of case TEEC_MEMREF_PARTIAL_OUTPUT


      default:
         break;
   }


   uint8_t *in_buffer2 = NULL;
   uintptr_t in_buffer2_size = 0;
   switch (
         TEEC_PARAM_TYPE_GET(operation->paramTypes, 1)
         )
   {
      case TEEC_VALUE_INPUT:
      case TEEC_VALUE_INOUT:
      {
         in_operation_param2_value_a = operation->params[1].value.a;
         in_operation_param2_value_b = operation->params[1].value.b;

         break;
      }

      case TEEC_MEMREF_TEMP_INPUT:
      case TEEC_MEMREF_TEMP_INOUT:
      {
         if (
               operation->params[1].tmpref.buffer == NULL
               )
         {
            return TEEC_ERROR_PARAM1_TEMPMEM_NULL;
         }
         if (
               operation->params[1].tmpref.size <= 0
               )
         {
            return TEEC_ERROR_PARAM1_TEMPMEM_LESS;
         }

         in_operation_param2_tmpref_buffer = (uint64_t) operation->params[1].tmpref.buffer;
         in_operation_param2_tmpref_size = operation->params[1].tmpref.size;

         in_buffer2_size = operation->params[1].tmpref.size;
         in_buffer2 = (uint8_t *) malloc(in_buffer2_size * sizeof(uint8_t));
         for (int isize = 0; isize < in_buffer2_size; isize++)
         {
            in_buffer2[isize] = (uint8_t) * ((uint8_t * )(operation->params[1].tmpref.buffer) + isize);
         }

         break;
      }

      case TEEC_MEMREF_TEMP_OUTPUT:
      {
         if (
               operation->params[1].tmpref.buffer == NULL
               )
         {
            return TEEC_ERROR_PARAM1_TEMPMEM_NULL;
         }
         if (
               operation->params[1].tmpref.size <= 0
               )
         {
            return TEEC_ERROR_PARAM1_TEMPMEM_LESS;
         }

         in_operation_param2_tmpref_buffer = (uint64_t) operation->params[1].tmpref.buffer;
         in_operation_param2_tmpref_size = operation->params[1].tmpref.size;

         break;
      }

      case TEEC_MEMREF_WHOLE:
      {
         switch (operation->params[1].memref.parent->flags)
         {
            case TEEC_MEM_INPUT:
            case TEEC_MEM_INOUT:
            {
               if (
                     operation->params[1].memref.parent->buffer == NULL
                     )
               {
                  return TEEC_ERROR_PARAM1_MEMREF_NULL;
               }
               if (
                     operation->params[1].memref.parent->size <= 0
                     )
               {
                  return TEEC_ERROR_PARAM1_MEMREF_LESS;
               }

               in_operation_param2_memref_parent =
                     (uint64_t) operation->params[1].memref.parent->buffer;
               in_operation_param2_memref_parent_flag =
                     (uint32_t) operation->params[1].memref.parent->flags;
               in_operation_param2_memref_size = operation->params[1].memref.size;

               in_buffer2_size = operation->params[1].memref.parent->size;
               in_buffer2 = (uint8_t *) malloc(in_buffer2_size * sizeof(uint8_t));
               for (int isize = 0; isize < in_buffer2_size; isize++)
               {
                  in_buffer2[isize] =
                        (uint8_t) * ((uint8_t * )(
                              operation->params[1].memref.parent->buffer
                        )
                                     + isize
                        );
               }

               break;
            }

            case TEEC_MEM_OUTPUT:
            {
               if (
                     operation->params[1].memref.parent->buffer == NULL
                     )
               {
                  return TEEC_ERROR_PARAM1_MEMREF_NULL;
               }
               if (
                     operation->params[1].memref.parent->size <= 0
                     )
               {
                  return TEEC_ERROR_PARAM1_MEMREF_LESS;
               }

               in_operation_param2_memref_parent =
                     (uint64_t) operation->params[1].memref.parent->buffer;
               in_operation_param2_memref_parent_flag =
                     (uint32_t) operation->params[1].memref.parent->flags;
               in_operation_param2_memref_size = operation->params[1].memref.size;

               break;
            }

            default:
            {
               return TEEC_ERROR_NO_SHAREMEMFLAG;
               break;
            }
         }

         break;
      }


      case TEEC_MEMREF_PARTIAL_INPUT:
      case TEEC_MEMREF_PARTIAL_INOUT:
      {
         if (operation->params[1].memref.parent->buffer == NULL)
         {
            return TEEC_ERROR_PARAM0_MEMREF_NULL;
         }
         if (operation->params[1].memref.parent->size <= 0)
         {
            return TEEC_ERROR_PARAM0_MEMREF_LESS;
         }

         in_operation_param2_memref_parent =
               (uint64_t) operation->params[1].memref.parent->buffer;
         in_operation_param2_memref_parent_flag =
               (uint32_t) operation->params[1].memref.parent->flags;
         in_operation_param2_memref_offset = operation->params[1].memref.offset;
         in_operation_param2_memref_size = operation->params[1].memref.size;

         in_buffer2_size = operation->params[1].memref.parent->size;
         in_buffer2 = (uint8_t *) malloc(in_buffer2_size * sizeof(uint8_t));
         for (int isize = 0; isize < in_buffer2_size; isize++)
         {
            in_buffer2[isize] =
                  (uint8_t) * ((uint8_t * )(operation->params[1].memref.parent->buffer) + isize);
         }

         break;
      }
         // end of case TEEC_MEMREF_PARTIAL_INPUT INOUT


      case TEEC_MEMREF_PARTIAL_OUTPUT:
      {
         if (operation->params[1].memref.parent->buffer == NULL)
         {
            return TEEC_ERROR_PARAM1_MEMREF_NULL;
         }
         if (operation->params[1].memref.parent->size <= 0)
         {
            return TEEC_ERROR_PARAM1_MEMREF_LESS;
         }

         in_operation_param2_memref_parent =
               (uint64_t) operation->params[1].memref.parent->buffer;
         in_operation_param2_memref_parent_flag =
               (uint32_t) operation->params[1].memref.parent->flags;
         in_operation_param2_memref_offset = operation->params[1].memref.offset;
         in_operation_param2_memref_size = operation->params[1].memref.size;

         in_buffer2_size = operation->params[1].memref.parent->size;
         in_buffer2 = (uint8_t *) malloc(in_buffer2_size * sizeof(uint8_t));
         for (int isize = 0; isize < in_buffer2_size; isize++)
         {
            in_buffer2[isize] = 0x0;
         }

         break;
      }
         // end of case TEEC_MEMREF_PARTIAL_OUTPUT


      default:
         break;
   }

   uint8_t *in_buffer3 = NULL;
   uintptr_t in_buffer3_size = 0;
   switch (
         TEEC_PARAM_TYPE_GET(operation->paramTypes, 2)
         )
   {
      case TEEC_VALUE_INPUT:
      case TEEC_VALUE_INOUT:
      {
         in_operation_param3_value_a = operation->params[2].value.a;
         in_operation_param3_value_b = operation->params[2].value.b;

         break;
      }

      case TEEC_MEMREF_TEMP_INPUT:
      case TEEC_MEMREF_TEMP_INOUT:
      {
         if (
               operation->params[2].tmpref.buffer == NULL
               )
         {
            return TEEC_ERROR_PARAM2_TEMPMEM_NULL;
         }
         if (
               operation->params[2].tmpref.size <= 0
               )
         {
            return TEEC_ERROR_PARAM2_TEMPMEM_LESS;
         }

         in_operation_param3_tmpref_buffer = (uint64_t) operation->params[2].tmpref.buffer;
         in_operation_param3_tmpref_size = operation->params[2].tmpref.size;

         in_buffer3_size = operation->params[2].tmpref.size;
         in_buffer3 = (uint8_t *) malloc(in_buffer3_size * sizeof(uint8_t));
         for (int isize = 0; isize < in_buffer3_size; isize++)
         {
            in_buffer3[isize] = (uint8_t) * ((uint8_t * )(operation->params[2].tmpref.buffer) + isize);
         }

         break;
      }

      case TEEC_MEMREF_TEMP_OUTPUT:
      {
         if (
               operation->params[2].tmpref.buffer == NULL
               )
         {
            return TEEC_ERROR_PARAM2_TEMPMEM_NULL;
         }
         if (
               operation->params[2].tmpref.size <= 0
               )
         {
            return TEEC_ERROR_PARAM2_TEMPMEM_LESS;
         }

         in_operation_param3_tmpref_buffer = (uint64_t) operation->params[2].tmpref.buffer;
         in_operation_param3_tmpref_size = operation->params[2].tmpref.size;

         break;
      }

      case TEEC_MEMREF_WHOLE:
      {
         switch (operation->params[2].memref.parent->flags)
         {
            case TEEC_MEM_INPUT:
            case TEEC_MEM_INOUT:
            {
               if (
                     operation->params[2].memref.parent->buffer == NULL
                     )
               {
                  return TEEC_ERROR_PARAM2_MEMREF_NULL;
               }
               if (
                     operation->params[2].memref.parent->size <= 0
                     )
               {
                  return TEEC_ERROR_PARAM2_MEMREF_LESS;
               }

               in_operation_param3_memref_parent =
                     (uint64_t) operation->params[2].memref.parent->buffer;
               in_operation_param3_memref_parent_flag =
                     (uint32_t) operation->params[2].memref.parent->flags;
               in_operation_param3_memref_size = operation->params[2].memref.size;

               in_buffer3_size = operation->params[2].memref.parent->size;
               in_buffer3 = (uint8_t *) malloc(in_buffer3_size * sizeof(uint8_t));
               for (int isize = 0; isize < in_buffer3_size; isize++)
               {
                  in_buffer3[isize] =
                        (uint8_t) * ((uint8_t * )(
                              operation->params[2].memref.parent->buffer
                        )
                                     + isize
                        );
               }

               break;
            }

            case TEEC_MEM_OUTPUT:
            {
               if (
                     operation->params[2].memref.parent->buffer == NULL
                     )
               {
                  return TEEC_ERROR_PARAM2_MEMREF_NULL;
               }
               if (
                     operation->params[2].memref.parent->size <= 0
                     )
               {
                  return TEEC_ERROR_PARAM2_MEMREF_LESS;
               }

               in_operation_param3_memref_parent =
                     (uint64_t) operation->params[2].memref.parent->buffer;
               in_operation_param3_memref_parent_flag =
                     (uint32_t) operation->params[2].memref.parent->flags;
               in_operation_param3_memref_size = operation->params[2].memref.size;

               break;
            }

            default:
            {
               return TEEC_ERROR_NO_SHAREMEMFLAG;
               break;
            }
         }

         break;
      }


      case TEEC_MEMREF_PARTIAL_INPUT:
      case TEEC_MEMREF_PARTIAL_INOUT:
      {
         if (operation->params[2].memref.parent->buffer == NULL)
         {
            return TEEC_ERROR_PARAM2_MEMREF_NULL;
         }
         if (operation->params[2].memref.parent->size <= 0)
         {
            return TEEC_ERROR_PARAM2_MEMREF_LESS;
         }

         in_operation_param3_memref_parent =
               (uint64_t) operation->params[2].memref.parent->buffer;
         in_operation_param3_memref_parent_flag =
               (uint32_t) operation->params[2].memref.parent->flags;
         in_operation_param3_memref_offset = operation->params[2].memref.offset;
         in_operation_param3_memref_size = operation->params[2].memref.size;

         in_buffer3_size = operation->params[2].memref.parent->size;
         in_buffer3 = (uint8_t *) malloc(in_buffer3_size * sizeof(uint8_t));
         for (int isize = 0; isize < in_buffer3_size; isize++)
         {
            in_buffer3[isize] =
                  (uint8_t) * ((uint8_t * )(operation->params[2].memref.parent->buffer) + isize);
         }

         break;
      }
         // end of case TEEC_MEMREF_PARTIAL_INPUT INOUT


      case TEEC_MEMREF_PARTIAL_OUTPUT:
      {
         if (operation->params[2].memref.parent->buffer == NULL)
         {
            return TEEC_ERROR_PARAM0_MEMREF_NULL;
         }
         if (operation->params[2].memref.parent->size <= 0)
         {
            return TEEC_ERROR_PARAM0_MEMREF_LESS;
         }

         in_operation_param3_memref_parent =
               (uint64_t) operation->params[2].memref.parent->buffer;
         in_operation_param3_memref_parent_flag =
               (uint32_t) operation->params[2].memref.parent->flags;
         in_operation_param3_memref_offset = operation->params[2].memref.offset;
         in_operation_param3_memref_size = operation->params[2].memref.size;

         in_buffer3_size = operation->params[2].memref.parent->size;
         in_buffer3 = (uint8_t *) malloc(in_buffer3_size * sizeof(uint8_t));
         for (int isize = 0; isize < in_buffer3_size; isize++)
         {
            in_buffer3[isize] = 0x0;
         }

         break;
      }
         // end of case TEEC_MEMREF_PARTIAL_OUTPUT

      default:
         break;
   }


   uint8_t *in_buffer4 = NULL;
   uintptr_t in_buffer4_size = 0;
   switch (
         TEEC_PARAM_TYPE_GET(operation->paramTypes, 3)
         )
   {
      case TEEC_VALUE_INPUT:
      case TEEC_VALUE_INOUT:
      {
         in_operation_param4_value_a = operation->params[3].value.a;
         in_operation_param4_value_b = operation->params[3].value.b;

         break;
      }

      case TEEC_MEMREF_TEMP_INPUT:
      case TEEC_MEMREF_TEMP_INOUT:
      {
         if (
               operation->params[3].tmpref.buffer == NULL
               )
         {
            return TEEC_ERROR_PARAM3_TEMPMEM_NULL;
         }
         if (
               operation->params[3].tmpref.size <= 0
               )
         {
            return TEEC_ERROR_PARAM3_TEMPMEM_LESS;
         }

         in_operation_param4_tmpref_buffer = (uint64_t) operation->params[3].tmpref.buffer;
         in_operation_param4_tmpref_size = operation->params[3].tmpref.size;

         in_buffer4_size = operation->params[3].tmpref.size;
         in_buffer4 = (uint8_t *) malloc(in_buffer4_size * sizeof(uint8_t));
         for (int isize = 0; isize < in_buffer4_size; isize++)
         {
            in_buffer4[isize] = (uint8_t) * ((uint8_t * )(operation->params[3].tmpref.buffer) + isize);
         }

         break;
      }

      case TEEC_MEMREF_TEMP_OUTPUT:
      {
         if (
               operation->params[3].tmpref.buffer == NULL
               )
         {
            return TEEC_ERROR_PARAM3_TEMPMEM_NULL;
         }
         if (
               operation->params[3].tmpref.size <= 0
               )
         {
            return TEEC_ERROR_PARAM3_TEMPMEM_LESS;
         }

         in_operation_param4_tmpref_buffer = (uint64_t) operation->params[3].tmpref.buffer;
         in_operation_param4_tmpref_size = operation->params[3].tmpref.size;

         break;
      }


      case TEEC_MEMREF_WHOLE:
      {
         switch (operation->params[3].memref.parent->flags)
         {
            case TEEC_MEM_INPUT:
            case TEEC_MEM_INOUT:
            {
               if (
                     operation->params[3].memref.parent->buffer == NULL
                     )
               {
                  return TEEC_ERROR_PARAM3_MEMREF_NULL;
               }
               if (
                     operation->params[3].memref.parent->size <= 0
                     )
               {
                  return TEEC_ERROR_PARAM3_MEMREF_LESS;
               }

               in_operation_param4_memref_parent =
                     (uint64_t) operation->params[3].memref.parent->buffer;
               in_operation_param4_memref_parent_flag =
                     (uint32_t) operation->params[3].memref.parent->flags;
               in_operation_param4_memref_size = operation->params[3].memref.size;

               in_buffer4_size = operation->params[3].memref.parent->size;
               in_buffer4 = (uint8_t *) malloc(in_buffer4_size * sizeof(uint8_t));
               for (int isize = 0; isize < in_buffer4_size; isize++)
               {
                  in_buffer4[isize] =
                        (uint8_t) * ((uint8_t * )(
                              operation->params[3].memref.parent->buffer
                        )
                                     + isize
                        );
               }

               break;
            }

            case TEEC_MEM_OUTPUT:
            {
               if (
                     operation->params[3].memref.parent->buffer == NULL
                     )
               {
                  return TEEC_ERROR_PARAM3_MEMREF_NULL;
               }
               if (
                     operation->params[3].memref.parent->size <= 0
                     )
               {
                  return TEEC_ERROR_PARAM3_MEMREF_LESS;
               }

               in_operation_param4_memref_parent =
                     (uint64_t) operation->params[3].memref.parent->buffer;
               in_operation_param4_memref_parent_flag =
                     (uint32_t) operation->params[3].memref.parent->flags;
               in_operation_param4_memref_size = operation->params[3].memref.size;

               break;
            }

            default:
            {
               return TEEC_ERROR_NO_SHAREMEMFLAG;
               break;
            }
         }

         break;
      }


      case TEEC_MEMREF_PARTIAL_INPUT:
      case TEEC_MEMREF_PARTIAL_INOUT:
      {
         if (operation->params[3].memref.parent->buffer == NULL)
         {
            return TEEC_ERROR_PARAM3_MEMREF_NULL;
         }
         if (operation->params[3].memref.parent->size <= 0)
         {
            return TEEC_ERROR_PARAM3_MEMREF_LESS;
         }

         in_operation_param4_memref_parent =
               (uint64_t) operation->params[3].memref.parent->buffer;
         in_operation_param4_memref_parent_flag =
               (uint32_t) operation->params[3].memref.parent->flags;
         in_operation_param4_memref_offset = operation->params[3].memref.offset;
         in_operation_param4_memref_size = operation->params[3].memref.size;

         in_buffer4_size = operation->params[3].memref.parent->size;
         in_buffer4 = (uint8_t *) malloc(in_buffer4_size * sizeof(uint8_t));
         for (int isize = 0; isize < in_buffer4_size; isize++)
         {
            in_buffer4[isize] =
                  (uint8_t) * ((uint8_t * )(operation->params[3].memref.parent->buffer) + isize);
         }

         break;
      }
         // end of case TEEC_MEMREF_PARTIAL_INPUT INOUT


      case TEEC_MEMREF_PARTIAL_OUTPUT:
      {
         if (operation->params[3].memref.parent->buffer == NULL)
         {
            return TEEC_ERROR_PARAM0_MEMREF_NULL;
         }
         if (operation->params[3].memref.parent->size <= 0)
         {
            return TEEC_ERROR_PARAM0_MEMREF_LESS;
         }

         in_operation_param4_memref_parent =
               (uint64_t) operation->params[3].memref.parent->buffer;
         in_operation_param4_memref_parent_flag =
               (uint32_t) operation->params[3].memref.parent->flags;
         in_operation_param4_memref_offset = operation->params[3].memref.offset;
         in_operation_param4_memref_size = operation->params[3].memref.size;

         in_buffer4_size = operation->params[3].memref.parent->size;
         in_buffer4 = (uint8_t *) malloc(in_buffer4_size * sizeof(uint8_t));
         for (int isize = 0; isize < in_buffer4_size; isize++)
         {
            in_buffer4[isize] = 0x0;
         }

         break;
      }
         // end of case TEEC_MEMREF_PARTIAL_OUTPUT


      default:
         break;
   }


   in_operation_session = (uint64_t) operation->session;
   in_operation_cancelflag = operation->cancel_flag;

   if (returnOrigin == NULL)
   {
      in_returnorigin = 0;
   } else
   {
      in_returnorigin = *returnOrigin;
   }

   rs_invokecommand_ins =
         client->externc_teec_invokecommand(
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
               in_buffer1_size,
               in_buffer2,
               in_buffer2_size,
               in_buffer3,
               in_buffer3_size,
               in_buffer4,
               in_buffer4_size
         );

   if (rs_invokecommand_ins.flag == 1)
   {
      std::cout << "libteecc: invoke token null" << std::endl;
      return TEEC_ERROR_TOKEN_NULL;
   }
   if (rs_invokecommand_ins.flag == 2)
   {
      std::cout << "libteecc: invoke jwt validate error" << std::endl;
      return TEEC_ERROR_JWTVALIDATE_FAIL;
   }
   if (rs_invokecommand_ins.teecresult == TEEC_SUCCESS)
   {
      session->session_id = rs_invokecommand_ins.session_sessionid;
      session->service_id.timeLow = rs_invokecommand_ins.session_serviceid_timelow;
      session->service_id.timeMid = rs_invokecommand_ins.session_serviceid_timemid;
      session->service_id.timeHiAndVersion = rs_invokecommand_ins.session_serviceid_timehiandver;
      if (rs_invokecommand_ins.session_serviceid_clockseqandnode_outsize <= 8 &&
          rs_invokecommand_ins.session_serviceid_clockseqandnode_outsize > 0 &&
          rs_invokecommand_ins.session_serviceid_clockseqandnode != NULL &&
          session->service_id.clockSeqAndNode != NULL
            )
      {
         for (int i = 0; i < rs_invokecommand_ins.session_serviceid_clockseqandnode_outsize; i++)
         {
            session->service_id.clockSeqAndNode[i] =
                  (uint8_t)(rs_invokecommand_ins.session_serviceid_clockseqandnode[i] & 0x000000ff);
         }
      } else
      {
         for (int i = 0; i < 8; i++)
         {
            session->service_id.clockSeqAndNode[i] = 0;
         }
      }
      session->ops_cnt = rs_invokecommand_ins.session_opscnt;
      session->head.next = (struct ListNode *) rs_invokecommand_ins.session_head_next;
      session->head.prev = (struct ListNode *) rs_invokecommand_ins.session_head_prev;
      session->context = (TEEC_Context *) rs_invokecommand_ins.session_context;

      operation->started = rs_invokecommand_ins.operation_started;
      operation->paramTypes = rs_invokecommand_ins.operation_paramtypes;

      switch (
            TEEC_PARAM_TYPE_GET(rs_invokecommand_ins.operation_paramtypes, 0)
            )
      {
         case TEEC_VALUE_OUTPUT:
         case TEEC_VALUE_INOUT:
         {
            operation->params[0].value.a = rs_invokecommand_ins.operation_param1_value_a;
            operation->params[0].value.b = rs_invokecommand_ins.operation_param1_value_b;

            break;
         }

         case TEEC_MEMREF_TEMP_OUTPUT:
         case TEEC_MEMREF_TEMP_INOUT:
         {
            if (operation->params[0].tmpref.buffer == NULL)
            {
               return TEEC_ERROR_PARAM0_TEMPMEM_NULL;
            }

            if (operation->params[0].tmpref.size <
                rs_invokecommand_ins.buffer1_outsize
                  )
            {
               return TEEC_ERROR_PARAM0_TEMPMEM_LESS;
            }

            if (rs_invokecommand_ins.buffer1 != NULL &&
                rs_invokecommand_ins.buffer1_outsize > 0)
            {
               for (int iind = 0; iind < rs_invokecommand_ins.buffer1_outsize; iind++)
               {
                  *((uint8_t * )(operation->params[0].tmpref.buffer) + iind) =
                        *(rs_invokecommand_ins.buffer1 + iind);
               }
               operation->params[0].tmpref.size = rs_invokecommand_ins.buffer1_outsize;
            }

            break;
         }


         case TEEC_MEMREF_WHOLE:
         {
            operation->params[0].memref.parent->flags =
                  rs_invokecommand_ins.operation_param1_memref_parent_flag;
            switch (operation->params[0].memref.parent->flags)
            {
               case TEEC_MEM_OUTPUT:
               case TEEC_MEM_INOUT:
               {
                  if (
                        operation->params[0].memref.parent->buffer == NULL
                        )
                  {
                     return TEEC_ERROR_PARAM0_MEMREF_NULL;
                  }
                  if (
                        operation->params[0].memref.parent->size <
                        rs_invokecommand_ins.buffer1_outsize
                        )
                  {
                     return TEEC_ERROR_PARAM0_MEMREF_LESS;
                  }

                  if (rs_invokecommand_ins.buffer1 != NULL &&
                      rs_invokecommand_ins.buffer1_outsize > 0)
                  {
                     for (int iind = 0; iind < rs_invokecommand_ins.buffer1_outsize; iind++)
                     {
                        *((uint8_t * )(operation->params[0].memref.parent->buffer) + iind) =
                              *(rs_invokecommand_ins.buffer1 + iind);
                     }
                     operation->params[0].memref.size = rs_invokecommand_ins.buffer1_outsize;
                     operation->params[0].memref.parent->size = rs_invokecommand_ins.buffer1_outsize;
                  }

                  break;
               }

               default:
                  break;
            }

            break;

         }
            // end of case TEEC_MEMREF_WHOLE:


         case TEEC_MEMREF_PARTIAL_OUTPUT:
         case TEEC_MEMREF_PARTIAL_INOUT:
         {
            if (operation->params[0].memref.parent->buffer == NULL)
            {
               return TEEC_ERROR_PARAM0_MEMREF_NULL;
            }
            if (operation->params[0].memref.parent->size <
                rs_invokecommand_ins.buffer1_outsize
                  )
            {
               return TEEC_ERROR_PARAM0_MEMREF_LESS;
            }

            if (rs_invokecommand_ins.buffer1 != NULL &&
                rs_invokecommand_ins.buffer1_outsize > 0)
            {
               for (int iind = 0; iind < rs_invokecommand_ins.buffer1_outsize; iind++)
               {
                  *((uint8_t * )(operation->params[0].memref.parent->buffer) + iind) =
                        *(rs_invokecommand_ins.buffer1 + iind);
               }
               operation->params[0].memref.parent->size = rs_invokecommand_ins.buffer1_outsize;

               operation->params[0].memref.offset = rs_invokecommand_ins.operation_param1_memref_offset;
               operation->params[0].memref.size = rs_invokecommand_ins.operation_param1_memref_size;
            }

            break;
         }
            // end of case TEEC_MEMREF_PARTIAL_OUTPUT, INOUT


         default:
            break;
      }

      operation->params[0].ionref.ion_share_fd = rs_invokecommand_ins.operation_param1_ionref_ionsharefd;
      operation->params[0].ionref.ion_size = rs_invokecommand_ins.operation_param1_ionref_ionsize;


      switch (
            TEEC_PARAM_TYPE_GET(rs_invokecommand_ins.operation_paramtypes, 1)
            )
      {
         case TEEC_VALUE_OUTPUT:
         case TEEC_VALUE_INOUT:
         {
            operation->params[1].value.a = rs_invokecommand_ins.operation_param2_value_a;
            operation->params[1].value.b = rs_invokecommand_ins.operation_param2_value_b;

            break;
         }

         case TEEC_MEMREF_TEMP_OUTPUT:
         case TEEC_MEMREF_TEMP_INOUT:
         {
            if (operation->params[1].tmpref.buffer == NULL)
            {
               return TEEC_ERROR_PARAM0_TEMPMEM_NULL;
            }

            if (operation->params[1].tmpref.size <
                rs_invokecommand_ins.buffer2_outsize
                  )
            {
               return TEEC_ERROR_PARAM0_TEMPMEM_LESS;
            }

            if (rs_invokecommand_ins.buffer2 != NULL &&
                rs_invokecommand_ins.buffer2_outsize > 0)
            {
               for (int iind = 0; iind < rs_invokecommand_ins.buffer2_outsize; iind++)
               {
                  *((uint8_t * )(operation->params[1].tmpref.buffer) + iind) =
                        *(rs_invokecommand_ins.buffer2 + iind);
               }
               operation->params[1].tmpref.size = rs_invokecommand_ins.buffer2_outsize;
            }

            break;
         }


         case TEEC_MEMREF_WHOLE:
         {
            operation->params[1].memref.parent->flags =
                  rs_invokecommand_ins.operation_param2_memref_parent_flag;
            switch (operation->params[1].memref.parent->flags)
            {
               case TEEC_MEM_OUTPUT:
               case TEEC_MEM_INOUT:
               {
                  if (
                        operation->params[1].memref.parent->buffer == NULL
                        )
                  {
                     return TEEC_ERROR_PARAM1_MEMREF_NULL;
                  }
                  if (
                        operation->params[1].memref.parent->size <
                        rs_invokecommand_ins.buffer2_outsize
                        )
                  {
                     return TEEC_ERROR_PARAM1_MEMREF_LESS;
                  }

                  if (rs_invokecommand_ins.buffer2 != NULL &&
                      rs_invokecommand_ins.buffer2_outsize > 0)
                  {
                     for (int iind = 0; iind < rs_invokecommand_ins.buffer2_outsize; iind++)
                     {
                        *((uint8_t * )(operation->params[1].memref.parent->buffer) + iind) =
                              *(rs_invokecommand_ins.buffer2 + iind);
                     }
                     operation->params[1].memref.size = rs_invokecommand_ins.buffer2_outsize;
                     operation->params[1].memref.parent->size = rs_invokecommand_ins.buffer2_outsize;
                  }

                  break;
               }

               default:
                  break;
            }

            break;
         }


         case TEEC_MEMREF_PARTIAL_OUTPUT:
         case TEEC_MEMREF_PARTIAL_INOUT:
         {
            if (operation->params[1].memref.parent->buffer == NULL)
            {
               return TEEC_ERROR_PARAM1_MEMREF_NULL;
            }
            if (operation->params[1].memref.parent->size <
                rs_invokecommand_ins.buffer2_outsize
                  )
            {
               return TEEC_ERROR_PARAM1_MEMREF_LESS;
            }

            if (rs_invokecommand_ins.buffer2 != NULL &&
                rs_invokecommand_ins.buffer2_outsize > 0)
            {
               for (int iind = 0; iind < rs_invokecommand_ins.buffer2_outsize; iind++)
               {
                  *((uint8_t * )(operation->params[1].memref.parent->buffer) + iind) =
                        *(rs_invokecommand_ins.buffer2 + iind);
               }
               operation->params[1].memref.parent->size = rs_invokecommand_ins.buffer2_outsize;

               operation->params[1].memref.offset = rs_invokecommand_ins.operation_param2_memref_offset;
               operation->params[1].memref.size = rs_invokecommand_ins.operation_param2_memref_size;
            }

            break;
         }
            // end of case TEEC_MEMREF_PARTIAL_OUTPUT, INOUT


         default:
            break;
      }

      operation->params[1].ionref.ion_share_fd = rs_invokecommand_ins.operation_param2_ionref_ionsharefd;
      operation->params[1].ionref.ion_size = rs_invokecommand_ins.operation_param2_ionref_ionsize;


      switch (
            TEEC_PARAM_TYPE_GET(rs_invokecommand_ins.operation_paramtypes, 2)
            )
      {
         case TEEC_VALUE_OUTPUT:
         case TEEC_VALUE_INOUT:
         {
            operation->params[2].value.a = rs_invokecommand_ins.operation_param3_value_a;
            operation->params[2].value.b = rs_invokecommand_ins.operation_param3_value_b;

            break;
         }

         case TEEC_MEMREF_TEMP_OUTPUT:
         case TEEC_MEMREF_TEMP_INOUT:
         {
            if (operation->params[2].tmpref.buffer == NULL)
            {
               return TEEC_ERROR_PARAM0_TEMPMEM_NULL;
            }

            if (operation->params[2].tmpref.size <
                rs_invokecommand_ins.buffer3_outsize
                  )
            {
               return TEEC_ERROR_PARAM0_TEMPMEM_LESS;
            }

            if (rs_invokecommand_ins.buffer3 != NULL &&
                rs_invokecommand_ins.buffer3_outsize > 0)
            {
               for (int iind = 0; iind < rs_invokecommand_ins.buffer3_outsize; iind++)
               {
                  *((uint8_t * )(operation->params[2].tmpref.buffer) + iind) =
                        *(rs_invokecommand_ins.buffer3 + iind);
               }
               operation->params[2].tmpref.size = rs_invokecommand_ins.buffer3_outsize;
            }

            break;
         }


         case TEEC_MEMREF_WHOLE:
         {
            operation->params[2].memref.parent->flags =
                  rs_invokecommand_ins.operation_param3_memref_parent_flag;
            switch (operation->params[2].memref.parent->flags)
            {
               case TEEC_MEM_OUTPUT:
               case TEEC_MEM_INOUT:
               {
                  if (
                        operation->params[2].memref.parent->buffer == NULL
                        )
                  {
                     return TEEC_ERROR_PARAM2_MEMREF_NULL;
                  }
                  if (
                        operation->params[2].memref.parent->size <
                        rs_invokecommand_ins.buffer3_outsize
                        )
                  {
                     return TEEC_ERROR_PARAM2_MEMREF_LESS;
                  }

                  if (rs_invokecommand_ins.buffer3 != NULL &&
                      rs_invokecommand_ins.buffer3_outsize > 0)
                  {
                     for (int iind = 0; iind < rs_invokecommand_ins.buffer3_outsize; iind++)
                     {
                        *((uint8_t * )(operation->params[2].memref.parent->buffer) + iind) =
                              *(rs_invokecommand_ins.buffer3 + iind);
                     }
                     operation->params[2].memref.size = rs_invokecommand_ins.buffer3_outsize;
                     operation->params[2].memref.parent->size = rs_invokecommand_ins.buffer3_outsize;
                  }

                  break;
               }

               default:
                  break;
            }

            break;

         }


         case TEEC_MEMREF_PARTIAL_OUTPUT:
         case TEEC_MEMREF_PARTIAL_INOUT:
         {
            if (operation->params[2].memref.parent->buffer == NULL)
            {
               return TEEC_ERROR_PARAM2_MEMREF_NULL;
            }
            if (operation->params[2].memref.parent->size <
                rs_invokecommand_ins.buffer3_outsize
                  )
            {
               return TEEC_ERROR_PARAM2_MEMREF_LESS;
            }

            if (rs_invokecommand_ins.buffer3 != NULL &&
                rs_invokecommand_ins.buffer3_outsize > 0)
            {
               for (int iind = 0; iind < rs_invokecommand_ins.buffer3_outsize; iind++)
               {
                  *((uint8_t * )(operation->params[2].memref.parent->buffer) + iind) =
                        *(rs_invokecommand_ins.buffer3 + iind);
               }
               operation->params[2].memref.parent->size = rs_invokecommand_ins.buffer3_outsize;

               operation->params[2].memref.offset = rs_invokecommand_ins.operation_param3_memref_offset;
               operation->params[2].memref.size = rs_invokecommand_ins.operation_param3_memref_size;
            }

            break;
         }
            // end of case TEEC_MEMREF_PARTIAL_OUTPUT, INOUT


         default:
            break;
      }

      operation->params[2].ionref.ion_share_fd = rs_invokecommand_ins.operation_param3_ionref_ionsharefd;
      operation->params[2].ionref.ion_size = rs_invokecommand_ins.operation_param3_ionref_ionsize;


      switch (
            TEEC_PARAM_TYPE_GET(rs_invokecommand_ins.operation_paramtypes, 3)
            )
      {
         case TEEC_VALUE_OUTPUT:
         case TEEC_VALUE_INOUT:
         {
            operation->params[3].value.a = rs_invokecommand_ins.operation_param4_value_a;
            operation->params[3].value.b = rs_invokecommand_ins.operation_param4_value_b;

            break;
         }

         case TEEC_MEMREF_TEMP_OUTPUT:
         case TEEC_MEMREF_TEMP_INOUT:
         {
            if (operation->params[3].tmpref.buffer == NULL)
            {
               return TEEC_ERROR_PARAM0_TEMPMEM_NULL;
            }

            if (operation->params[3].tmpref.size <
                rs_invokecommand_ins.buffer4_outsize
                  )
            {
               return TEEC_ERROR_PARAM0_TEMPMEM_LESS;
            }

            if (rs_invokecommand_ins.buffer4 != NULL &&
                rs_invokecommand_ins.buffer4_outsize > 0)
            {
               for (int iind = 0; iind < rs_invokecommand_ins.buffer4_outsize; iind++)
               {
                  *((uint8_t * )(operation->params[3].tmpref.buffer) + iind) =
                        *(rs_invokecommand_ins.buffer4 + iind);
               }
               operation->params[3].tmpref.size = rs_invokecommand_ins.buffer4_outsize;
            }

            break;
         }


         case TEEC_MEMREF_WHOLE:
         {
            operation->params[3].memref.parent->flags =
                  rs_invokecommand_ins.operation_param4_memref_parent_flag;
            switch (operation->params[3].memref.parent->flags)
            {
               case TEEC_MEM_OUTPUT:
               case TEEC_MEM_INOUT:
               {
                  if (
                        operation->params[3].memref.parent->buffer == NULL
                        )
                  {
                     return TEEC_ERROR_PARAM3_MEMREF_NULL;
                  }
                  if (
                        operation->params[3].memref.parent->size <
                        rs_invokecommand_ins.buffer4_outsize
                        )
                  {
                     return TEEC_ERROR_PARAM3_MEMREF_LESS;
                  }

                  if (rs_invokecommand_ins.buffer4 != NULL &&
                      rs_invokecommand_ins.buffer4_outsize > 0)
                  {
                     for (int iind = 0; iind < rs_invokecommand_ins.buffer4_outsize; iind++)
                     {
                        *((uint8_t * )(operation->params[3].memref.parent->buffer) + iind) =
                              *(rs_invokecommand_ins.buffer4 + iind);
                     }
                     operation->params[3].memref.size = rs_invokecommand_ins.buffer3_outsize;
                     operation->params[3].memref.parent->size = rs_invokecommand_ins.buffer3_outsize;
                  }

                  break;
               }

               default:
                  break;
            }

            break;
         }


         case TEEC_MEMREF_PARTIAL_OUTPUT:
         case TEEC_MEMREF_PARTIAL_INOUT:
         {
            if (operation->params[3].memref.parent->buffer == NULL)
            {
               return TEEC_ERROR_PARAM3_MEMREF_NULL;
            }
            if (operation->params[3].memref.parent->size <
                rs_invokecommand_ins.buffer4_outsize
                  )
            {
               return TEEC_ERROR_PARAM3_MEMREF_LESS;
            }

            if (rs_invokecommand_ins.buffer4 != NULL &&
                rs_invokecommand_ins.buffer4_outsize > 0)
            {
               for (int iind = 0; iind < rs_invokecommand_ins.buffer4_outsize; iind++)
               {
                  *((uint8_t * )(operation->params[3].memref.parent->buffer) + iind) =
                        *(rs_invokecommand_ins.buffer4 + iind);
               }
               operation->params[3].memref.parent->size = rs_invokecommand_ins.buffer4_outsize;

               operation->params[3].memref.offset = rs_invokecommand_ins.operation_param4_memref_offset;
               operation->params[3].memref.size = rs_invokecommand_ins.operation_param4_memref_size;
            }

            break;
         }
            // end of case TEEC_MEMREF_PARTIAL_OUTPUT, INOUT


         default:
            break;
      }

      operation->params[3].ionref.ion_share_fd = rs_invokecommand_ins.operation_param4_ionref_ionsharefd;
      operation->params[3].ionref.ion_size = rs_invokecommand_ins.operation_param4_ionref_ionsize;

      operation->session = (TEEC_Session *) rs_invokecommand_ins.operation_session;
      operation->cancel_flag = rs_invokecommand_ins.operation_cancelflag;

      if (returnOrigin != NULL)
      {
         *returnOrigin = in_returnorigin;
      }
   }
   if (ltFlag == 0){
      std::cout  << "session " <<in_session_sessionid<< " wait for live transfer " << std::endl;
      sleep(5);  //wait for hotmove
/*      if(channel_flag == -1){
         gpp_channel.reset();
         delete gpp_channel.get();
         delete client;
         channel_flag = 0;
      }*/
      pthread_mutex_lock(&mutex_ltflag);
      ltFlag = 1;
      ltnum += 1;
      channel_flag = -1;
      pthread_mutex_unlock(&mutex_ltflag);
   }

   return static_cast<TEEC_Result>(rs_invokecommand_ins.teecresult);

}

void
TEEC_CloseSession(TEEC_Session *session)
{
   if (gpp_channel == NULL)
   {
      printf("libteec: the grpc client or channel is null, when executing TEEC_CloseSession. \n");
      return;
   }

   uint32_t in_session_sessionid;
   uint32_t in_session_serviceid_timelow;
   uint32_t in_session_serviceid_timemid;
   uint32_t in_session_serviceid_timehiandver;
   uint8_t in_session_serviceid_clockseqandnode[8];
   uintptr_t in_session_serviceid_clockseqandnode_size;
   uint32_t in_session_opscnt;
   uint64_t in_session_head_next;
   int64_t in_session_head_prev;
   uint64_t in_session_context;

   if (session == NULL)
   {
      return;
   }
   struct retstru_teec_closesession rs_closesession_ins;

   in_session_sessionid = session->session_id;
   in_session_serviceid_timelow = session->service_id.timeLow;
   in_session_serviceid_timemid = session->service_id.timeMid;
   in_session_serviceid_timehiandver = session->service_id.timeHiAndVersion;
   if (
         session->service_id.clockSeqAndNode != NULL
         )
   {
      for (int i = 0; i < 8; i++)
      {
         in_session_serviceid_clockseqandnode[i] =
               session->service_id.clockSeqAndNode[i];
      }
   } else
   {
      for (int i = 0; i < 8; i++)
      {
         in_session_serviceid_clockseqandnode[i] = 0;
      }
   }
   in_session_serviceid_clockseqandnode_size = 8;
   in_session_opscnt = session->ops_cnt;
   in_session_head_next = (uint64_t) session->head.next;
   in_session_head_prev = (uint64_t) session->head.prev;
   in_session_context = glob_scontaddr;

   rs_closesession_ins =
         client->externc_teec_closesession(
               in_session_sessionid,
               in_session_serviceid_timelow,
               in_session_serviceid_timemid,
               in_session_serviceid_timehiandver,
               in_session_serviceid_clockseqandnode,
               in_session_serviceid_clockseqandnode_size,
               in_session_opscnt,
               in_session_head_next,
               in_session_head_prev,
               in_session_context
         );

   if (rs_closesession_ins.flag == 1)
   {
      std::cout << "libteecc: closesession token null" << std::endl;
      return;
   }
   if (rs_closesession_ins.flag == 2)
   {
      std::cout << "libteecc: closesession jwt validate error" << std::endl;
      return;
   }
#if 0
   std::cout << "externc_teec_closesession: " << std::endl;
   std::cout << "gpp request sessionid: " << in_session_sessionid <<std::endl;
   std::cout << "gpp request context_addr: " << in_session_context <<std::endl;
   std::cout << "gpp reply   session_sessionid: 0x " << std::hex << std::setfill('0') << std::setw(8) <<rs_closesession_ins.session_sessionid  <<std::endl;
   std::cout << "gpp reply   session_context: 0x " << std::hex << std::setfill('0') << std::setw(16) <<rs_closesession_ins.session_context <<std::endl;
#endif
#if 0
   printf("ret session_serviceid_timelow          = 0x %8.8x\n",
     rs_closesession_ins.session_serviceid_timelow);
   printf("ret session_serviceid_timemid          = 0x %8.8x\n",
     rs_closesession_ins.session_serviceid_timemid);
   printf("ret session_serviceid_timehiandver     = 0x %8.8x\n",
          rs_closesession_ins.session_serviceid_timehiandver);
   if (
      rs_closesession_ins.session_serviceid_clockseqandnode_outsize > 0
      &&
      rs_closesession_ins.session_serviceid_clockseqandnode != NULL
      )
   {
      printf("ret session_serviceid_clockseqandnode  = \n");
      for (uintptr_t uisize = 0;
      uisize < rs_closesession_ins.session_serviceid_clockseqandnode_outsize;
      uisize ++)
      {
         printf(" %2.2x", *(rs_closesession_ins.session_serviceid_clockseqandnode + uisize));
      }
      printf("\n");
   }
   else
   {
      printf("ret            clockseqandnode addr    = 0x %16.16lx\n",
             (unsigned long)rs_closesession_ins.session_serviceid_clockseqandnode);
   }
   printf("ret            clockseqandnode_outsize = %ld\n",
          rs_closesession_ins.session_serviceid_clockseqandnode_outsize);
   printf("ret session_opscnt                     = 0x %8.8x\n",
          rs_closesession_ins.session_opscnt);
   printf("ret session_head_next                  = 0x %16.16lx\n",
     rs_closesession_ins.session_head_next);
   printf("ret session_head_prev                  = 0x %16.16lx\n",
     rs_closesession_ins.session_head_prev);
#endif
   session->session_id = rs_closesession_ins.session_sessionid;
   session->service_id.timeLow = rs_closesession_ins.session_serviceid_timelow;
   session->service_id.timeMid = rs_closesession_ins.session_serviceid_timemid;
   session->service_id.timeHiAndVersion = rs_closesession_ins.session_serviceid_timehiandver;
   if (rs_closesession_ins.session_serviceid_clockseqandnode_outsize <= 8 &&
       rs_closesession_ins.session_serviceid_clockseqandnode_outsize > 0 &&
       rs_closesession_ins.session_serviceid_clockseqandnode != NULL &&
       session->service_id.clockSeqAndNode != NULL
         )
   {
      for (int i = 0; i < rs_closesession_ins.session_serviceid_clockseqandnode_outsize; i++)
      {
         session->service_id.clockSeqAndNode[i] =
               (uint8_t)(rs_closesession_ins.session_serviceid_clockseqandnode[i] & 0x000000ff);
      }
   } else
   {
      for (int i = 0; i < 8; i++)
      {
         session->service_id.clockSeqAndNode[i] = 0;
      }
   }
   session->ops_cnt = rs_closesession_ins.session_opscnt;
   session->head.next = (struct ListNode *) rs_closesession_ins.session_head_next;
   session->head.prev = (struct ListNode *) rs_closesession_ins.session_head_prev;
   session->context = (TEEC_Context *) rs_closesession_ins.session_context;
   return;
}

TEEC_Result
TEEC_AllocateSharedMemory(
      TEEC_Context *context,
      TEEC_SharedMemory *sharedMem)
{
   if (context == NULL)
   {
      return TEEC_ERROR_BAD_PARAMETERS;
   }
   if (sharedMem == NULL)
   {
      return TEEC_ERROR_BAD_PARAMETERS;
   }
   if (sharedMem->size <= 0)
   {
      return TEEC_ERROR_BAD_PARAMETERS;
   }

   sharedMem->buffer = (uint8_t *) malloc(sharedMem->size);
   if (sharedMem->buffer == NULL)
   {
      return TEEC_ERROR_OUT_OF_MEMORY;
   }

   sharedMem->is_allocated = true;
   sharedMem->context = context;
   sharedMem->ops_cnt = 0xfffe;

   return TEEC_SUCCESS;
}

TEEC_Result
TEEC_RegisterSharedMemory(
      TEEC_Context *context,
      TEEC_SharedMemory *sharedMem)
{
   if (context == NULL)
   {
      return TEEC_ERROR_BAD_PARAMETERS;
   }
   if (sharedMem == NULL)
   {
      return TEEC_ERROR_BAD_PARAMETERS;
   }
   if (sharedMem->size <= 0)
   {
      return TEEC_ERROR_BAD_PARAMETERS;
   }

   if (sharedMem->buffer == NULL)
   {
      return TEEC_ERROR_BAD_PARAMETERS;
   }

   sharedMem->is_allocated = false;
   sharedMem->context = context;
   sharedMem->ops_cnt = 0xfffe;

   return TEEC_SUCCESS;
}

void
TEEC_ReleaseSharedMemory(
      TEEC_SharedMemory *sharedMem)
{
   if (sharedMem == NULL)
   {
      return;
   }
   if (sharedMem->buffer == NULL)
   {
      return;
   }

   sharedMem->ops_cnt = 0x0;
   if (sharedMem->is_allocated == true)
   {
      free(sharedMem->buffer);
   }
}


TEEC_Result
TEEC_DeployTa(
      char *infile_path,
      char *subdir,
      char *outfile_name
)
{

   if (infile_path == NULL)
   {
      return TEEC_INFILE_PATH_NULL;
   }

   std::string str_infile_path(infile_path);
   std::string str_subdir;
   std::string str_outfile_name;

   if (subdir != NULL)
   {
      str_subdir = std::string(subdir);
   }

   if (outfile_name != NULL)
   {
      str_outfile_name = std::string(outfile_name);
   }

   int iret;

   if (gpp_channel == NULL)
   {
      int igrpctls = grpc_tls;

      if (grpc_tls != 0 && grpc_tls != 1 && grpc_tls != 2)
      {
         std::cout << global_strcfgfile << " grpc_tls should be 0 or 1 or 2 " << std::endl;
         return TEEC_FAIL;
      }

      switch (igrpctls)
      {
         case 0:
         {
            gpp_channel = grpc::CreateChannel(global_target_str, grpc::InsecureChannelCredentials());

            break;
         }

         case 1:
         {
            if (!isFileExists_ifstream(global_servercacert_path))
            {
               std::cout << "error file : " << global_servercacert_path << " is not exist " << std::endl;
               return TEEC_FAIL;
            }

            std::string strcmd;
            FILE *pipe;
            char buffer[128];
            std::string result;

            std::string strdayseconds;
            char *resulttemp;
            const char slash[] = "\n";
            char *parresult;
            std::string strparresult;
            std::string willexpire("Certificate will expire");

            // 7 days in seconds
            strdayseconds = "604800";
            strcmd = "openssl x509 -enddate -noout -in " + global_servercacert_path + " -checkend " + strdayseconds;
            // system(strcmd.c_str());
            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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
               std::cout << "gpp '" << global_servercacert_path << "' will expire in 7 days, please reget it" << std::endl;
               return TEEC_FAIL;
            }

            auto servercacert = get_file_contents(global_servercacert_path);
            grpc::SslCredentialsOptions ssl_opts;
            ssl_opts.pem_root_certs = servercacert;
            std::shared_ptr <grpc::ChannelCredentials> creds = grpc::SslCredentials(ssl_opts);
            gpp_channel = grpc::CreateChannel(global_target_str, creds);

            break;
         }

         case 2:
         {
            if (!isFileExists_ifstream(global_servercacert_path))
            {
               std::cout << "error file : " << global_servercacert_path << " is not exist " << std::endl;
               return TEEC_FAIL;
            }
            if (!isFileExists_ifstream(global_clientkey_path))
            {
               std::cout << "error file : " << global_clientkey_path << " is not exist " << std::endl;
               return TEEC_FAIL;
            }
            if (!isFileExists_ifstream(global_clientcert_path))
            {
               std::cout << "error file : " << global_clientcert_path << " is not exist " << std::endl;
               return TEEC_FAIL;
            }

            std::string strcmd;
            FILE *pipe;
            char buffer[128];
            std::string result;

            std::string strdayseconds;
            char *resulttemp;
            const char slash[] = "\n";
            char *parresult;
            std::string strparresult;
            std::string willexpire("Certificate will expire");

            // 7 days in seconds
            strdayseconds = "604800";
            strcmd = "openssl x509 -enddate -noout -in " + global_servercacert_path + " -checkend " + strdayseconds;
            // system(strcmd.c_str());
            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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
               std::cout << "libteecc '" << global_servercacert_path << "' will expire in 7 days, please reget it"
                         << std::endl;
               return TEEC_FAIL;
            }

            // 7 days in seconds
            strdayseconds = "604800";
            strcmd = "openssl x509 -enddate -noout -in " + global_clientcert_path + " -checkend " + strdayseconds;
            // system(strcmd.c_str());
            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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
               std::cout << "libteecc '" << global_clientcert_path << "' will expire in 7 days, please reget it" << std::endl;
               return TEEC_FAIL;
            }
            strcmd = "openssl rsa -in " + global_clientkey_path + " -out "
                     + global_clientkey_path + ".nopass";
            std::string nopass_clientkey_path = global_clientkey_path + ".nopass";

            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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

            strcmd = "openssl rsa -in " + nopass_clientkey_path + " -check -noout";
            // system(strcmd.c_str());
            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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
               std::cout << "libteecc '" + global_clientkey_path + "' integrity is broken" << std::endl;
               return TEEC_FAIL;
            }

            std::string sigfile_path = global_strcfgfiletemp + "/.teecc/certs/msg.sig";
            std::string msgfile_path = global_strcfgfiletemp + "/.teecc/certs/msg.txt";
            strcmd =
                  "openssl dgst -sha256 -sign " + nopass_clientkey_path + " -out " + sigfile_path + " " + msgfile_path;
            system(strcmd.c_str());
            // ${_openssl} x509 -in ${CRTPEM} -pubkey -out ${PUBPEM}
            std::string pubkeyfile_path = global_strcfgfiletemp + "/.teecc/certs/client_pubkey.pem";
            strcmd = "openssl x509 -in " + global_clientcert_path + " -pubkey -out " + pubkeyfile_path;
            system(strcmd.c_str());

            // ${_openssl} dgst -sha256 -verify ${PUBPEM} -signature msg.sig msg.txt
            strcmd = "openssl dgst -sha256 -verify " + pubkeyfile_path + " -signature " + sigfile_path + " " +
                     msgfile_path;
            // system(strcmd.c_str());
            pipe = popen(strcmd.c_str(), "r");
            if (!pipe)
            {
               std::cout << "libteecc popen '" << strcmd << "' failed" << std::endl;
               return TEEC_FAIL;
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
               std::cout << "libteecc '" + global_clientkey_path + "' is not matched with '" + global_clientcert_path + "'"
                         << std::endl;
               return TEEC_FAIL;
            }

            auto clientkey = get_file_contents(nopass_clientkey_path);
            strcmd = "rm -f " + global_clientkey_path + ".nopass";
            system(strcmd.c_str());
            strcmd = "rm -f " + pubkeyfile_path;
            system(strcmd.c_str());
            strcmd = "rm -f " + sigfile_path;
            system(strcmd.c_str());

            auto servercacert = get_file_contents(global_servercacert_path);
            auto clientcert = get_file_contents(global_clientcert_path);
            grpc::SslCredentialsOptions ssl_opts;
            ssl_opts.pem_root_certs = servercacert;
            ssl_opts.pem_private_key = clientkey;
            ssl_opts.pem_cert_chain = clientcert;
            std::shared_ptr <grpc::ChannelCredentials> creds = grpc::SslCredentials(ssl_opts);
            gpp_channel = grpc::CreateChannel(global_target_str, creds);

            break;
         }

         default:
         {
            gpp_channel = grpc::CreateChannel(global_target_str, grpc::InsecureChannelCredentials());
         }
      }

      client = new GppClient(
            gpp_channel
      );
   }

   iret = client->Upload(str_infile_path, str_subdir, str_outfile_name);

   return (TEEC_Result) iret;
}


TEEC_Result
TEEC_SetJwt(
      char *token
)
{
   if (token == NULL || sizeof(token) > 1024)
   {
      return TEEC_FAIL;
   }

   memset(glo_token, '\0', sizeof(glo_token));
   strcpy(glo_token, token);

   return TEEC_SUCCESS;
}


TEEC_Result
TEEC_UnsetJwt(
)
{
   memset(glo_token, '\0', sizeof(glo_token));
   strcpy(glo_token, "noToken");

   return TEEC_SUCCESS;
}



#ifdef __cplusplus
};
#endif
