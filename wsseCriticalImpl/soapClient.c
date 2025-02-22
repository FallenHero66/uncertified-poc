/* soapClient.c
   Generated by gSOAP 2.8.87 for wssedemo.h

gSOAP XML Web services tools
Copyright (C) 2000-2018, Robert van Engelen, Genivia Inc. All Rights Reserved.
The soapcpp2 tool and its generated software are released under the GPL.
This program is released under the GPL with the additional exemption that
compiling, linking, and/or using OpenSSL is allowed.
--------------------------------------------------------------------------------
A commercial use license is available from Genivia Inc., contact@genivia.com
--------------------------------------------------------------------------------
*/

#if defined(__BORLANDC__)
#pragma option push -w-8060
#pragma option push -w-8004
#endif
#include "soapH.h"
#ifdef __cplusplus
extern "C" {
#endif

SOAP_SOURCE_STAMP("@(#) soapClient.c ver 2.8.87 2019-08-26 14:37:56 GMT")


SOAP_FMAC5 int SOAP_FMAC6 soap_call_ns1__add(struct soap *soap, const char *soap_endpoint, const char *soap_action, double a, double b, double *result)
{	if (soap_send_ns1__add(soap, soap_endpoint, soap_action, a, b) || soap_recv_ns1__add(soap, result))
		return soap->error;
	return SOAP_OK;
}

SOAP_FMAC5 int SOAP_FMAC6 soap_send_ns1__add(struct soap *soap, const char *soap_endpoint, const char *soap_action, double a, double b)
{	struct ns1__add soap_tmp_ns1__add;
	if (soap_endpoint == NULL)
		soap_endpoint = "http://localhost:80";
	if (soap_action == NULL)
		soap_action = "";
	soap_tmp_ns1__add.a = a;
	soap_tmp_ns1__add.b = b;
	soap_begin(soap);
	soap->encodingStyle = "http://schemas.xmlsoap.org/soap/encoding/"; /* use SOAP encoding style */
	soap_serializeheader(soap);
	soap_serialize_ns1__add(soap, &soap_tmp_ns1__add);
	if (soap_begin_count(soap))
		return soap->error;
	if ((soap->mode & SOAP_IO_LENGTH))
	{	if (soap_envelope_begin_out(soap)
		 || soap_putheader(soap)
		 || soap_body_begin_out(soap)
		 || soap_put_ns1__add(soap, &soap_tmp_ns1__add, "ns1:add", "")
		 || soap_body_end_out(soap)
		 || soap_envelope_end_out(soap))
			 return soap->error;
	}
	if (soap_end_count(soap))
		return soap->error;
	if (soap_connect(soap, soap_endpoint, soap_action)
	 || soap_envelope_begin_out(soap)
	 || soap_putheader(soap)
	 || soap_body_begin_out(soap)
	 || soap_put_ns1__add(soap, &soap_tmp_ns1__add, "ns1:add", "")
	 || soap_body_end_out(soap)
	 || soap_envelope_end_out(soap)
	 || soap_end_send(soap))
		return soap_closesock(soap);
	return SOAP_OK;
}

SOAP_FMAC5 int SOAP_FMAC6 soap_recv_ns1__add(struct soap *soap, double *result)
{
	struct ns1__addResponse *soap_tmp_ns1__addResponse;
	if (!result)
		return soap_closesock(soap);
	soap_default_double(soap, result);
	if (soap_begin_recv(soap)
	 || soap_envelope_begin_in(soap)
	 || soap_recv_header(soap)
	 || soap_body_begin_in(soap))
		return soap_closesock(soap);
	if (soap_recv_fault(soap, 1))
		return soap->error;
	soap_tmp_ns1__addResponse = soap_get_ns1__addResponse(soap, NULL, "", NULL);
	if (!soap_tmp_ns1__addResponse || soap->error)
		return soap_recv_fault(soap, 0);
	if (soap_body_end_in(soap)
	 || soap_envelope_end_in(soap)
	 || soap_end_recv(soap))
		return soap_closesock(soap);
	if (result && soap_tmp_ns1__addResponse->result)
		*result = *soap_tmp_ns1__addResponse->result;
	return soap_closesock(soap);
}

SOAP_FMAC5 int SOAP_FMAC6 soap_call_ns1__sub(struct soap *soap, const char *soap_endpoint, const char *soap_action, double a, double b, double *result)
{	if (soap_send_ns1__sub(soap, soap_endpoint, soap_action, a, b) || soap_recv_ns1__sub(soap, result))
		return soap->error;
	return SOAP_OK;
}

SOAP_FMAC5 int SOAP_FMAC6 soap_send_ns1__sub(struct soap *soap, const char *soap_endpoint, const char *soap_action, double a, double b)
{	struct ns1__sub soap_tmp_ns1__sub;
	if (soap_endpoint == NULL)
		soap_endpoint = "http://localhost:80";
	if (soap_action == NULL)
		soap_action = "";
	soap_tmp_ns1__sub.a = a;
	soap_tmp_ns1__sub.b = b;
	soap_begin(soap);
	soap->encodingStyle = "http://schemas.xmlsoap.org/soap/encoding/"; /* use SOAP encoding style */
	soap_serializeheader(soap);
	soap_serialize_ns1__sub(soap, &soap_tmp_ns1__sub);
	if (soap_begin_count(soap))
		return soap->error;
	if ((soap->mode & SOAP_IO_LENGTH))
	{	if (soap_envelope_begin_out(soap)
		 || soap_putheader(soap)
		 || soap_body_begin_out(soap)
		 || soap_put_ns1__sub(soap, &soap_tmp_ns1__sub, "ns1:sub", "")
		 || soap_body_end_out(soap)
		 || soap_envelope_end_out(soap))
			 return soap->error;
	}
	if (soap_end_count(soap))
		return soap->error;
	if (soap_connect(soap, soap_endpoint, soap_action)
	 || soap_envelope_begin_out(soap)
	 || soap_putheader(soap)
	 || soap_body_begin_out(soap)
	 || soap_put_ns1__sub(soap, &soap_tmp_ns1__sub, "ns1:sub", "")
	 || soap_body_end_out(soap)
	 || soap_envelope_end_out(soap)
	 || soap_end_send(soap))
		return soap_closesock(soap);
	return SOAP_OK;
}

SOAP_FMAC5 int SOAP_FMAC6 soap_recv_ns1__sub(struct soap *soap, double *result)
{
	struct ns1__subResponse *soap_tmp_ns1__subResponse;
	if (!result)
		return soap_closesock(soap);
	soap_default_double(soap, result);
	if (soap_begin_recv(soap)
	 || soap_envelope_begin_in(soap)
	 || soap_recv_header(soap)
	 || soap_body_begin_in(soap))
		return soap_closesock(soap);
	if (soap_recv_fault(soap, 1))
		return soap->error;
	soap_tmp_ns1__subResponse = soap_get_ns1__subResponse(soap, NULL, "", NULL);
	if (!soap_tmp_ns1__subResponse || soap->error)
		return soap_recv_fault(soap, 0);
	if (soap_body_end_in(soap)
	 || soap_envelope_end_in(soap)
	 || soap_end_recv(soap))
		return soap_closesock(soap);
	if (result && soap_tmp_ns1__subResponse->result)
		*result = *soap_tmp_ns1__subResponse->result;
	return soap_closesock(soap);
}

SOAP_FMAC5 int SOAP_FMAC6 soap_call_ns1__mul(struct soap *soap, const char *soap_endpoint, const char *soap_action, double a, double b, double *result)
{	if (soap_send_ns1__mul(soap, soap_endpoint, soap_action, a, b) || soap_recv_ns1__mul(soap, result))
		return soap->error;
	return SOAP_OK;
}

SOAP_FMAC5 int SOAP_FMAC6 soap_send_ns1__mul(struct soap *soap, const char *soap_endpoint, const char *soap_action, double a, double b)
{	struct ns1__mul soap_tmp_ns1__mul;
	if (soap_endpoint == NULL)
		soap_endpoint = "http://localhost:80";
	if (soap_action == NULL)
		soap_action = "";
	soap_tmp_ns1__mul.a = a;
	soap_tmp_ns1__mul.b = b;
	soap_begin(soap);
	soap->encodingStyle = "http://schemas.xmlsoap.org/soap/encoding/"; /* use SOAP encoding style */
	soap_serializeheader(soap);
	soap_serialize_ns1__mul(soap, &soap_tmp_ns1__mul);
	if (soap_begin_count(soap))
		return soap->error;
	if ((soap->mode & SOAP_IO_LENGTH))
	{	if (soap_envelope_begin_out(soap)
		 || soap_putheader(soap)
		 || soap_body_begin_out(soap)
		 || soap_put_ns1__mul(soap, &soap_tmp_ns1__mul, "ns1:mul", "")
		 || soap_body_end_out(soap)
		 || soap_envelope_end_out(soap))
			 return soap->error;
	}
	if (soap_end_count(soap))
		return soap->error;
	if (soap_connect(soap, soap_endpoint, soap_action)
	 || soap_envelope_begin_out(soap)
	 || soap_putheader(soap)
	 || soap_body_begin_out(soap)
	 || soap_put_ns1__mul(soap, &soap_tmp_ns1__mul, "ns1:mul", "")
	 || soap_body_end_out(soap)
	 || soap_envelope_end_out(soap)
	 || soap_end_send(soap))
		return soap_closesock(soap);
	return SOAP_OK;
}

SOAP_FMAC5 int SOAP_FMAC6 soap_recv_ns1__mul(struct soap *soap, double *result)
{
	struct ns1__mulResponse *soap_tmp_ns1__mulResponse;
	if (!result)
		return soap_closesock(soap);
	soap_default_double(soap, result);
	if (soap_begin_recv(soap)
	 || soap_envelope_begin_in(soap)
	 || soap_recv_header(soap)
	 || soap_body_begin_in(soap))
		return soap_closesock(soap);
	if (soap_recv_fault(soap, 1))
		return soap->error;
	soap_tmp_ns1__mulResponse = soap_get_ns1__mulResponse(soap, NULL, "", NULL);
	if (!soap_tmp_ns1__mulResponse || soap->error)
		return soap_recv_fault(soap, 0);
	if (soap_body_end_in(soap)
	 || soap_envelope_end_in(soap)
	 || soap_end_recv(soap))
		return soap_closesock(soap);
	if (result && soap_tmp_ns1__mulResponse->result)
		*result = *soap_tmp_ns1__mulResponse->result;
	return soap_closesock(soap);
}

SOAP_FMAC5 int SOAP_FMAC6 soap_call_ns1__div(struct soap *soap, const char *soap_endpoint, const char *soap_action, double a, double b, double *result)
{	if (soap_send_ns1__div(soap, soap_endpoint, soap_action, a, b) || soap_recv_ns1__div(soap, result))
		return soap->error;
	return SOAP_OK;
}

SOAP_FMAC5 int SOAP_FMAC6 soap_send_ns1__div(struct soap *soap, const char *soap_endpoint, const char *soap_action, double a, double b)
{	struct ns1__div soap_tmp_ns1__div;
	if (soap_endpoint == NULL)
		soap_endpoint = "http://localhost:80";
	if (soap_action == NULL)
		soap_action = "";
	soap_tmp_ns1__div.a = a;
	soap_tmp_ns1__div.b = b;
	soap_begin(soap);
	soap->encodingStyle = "http://schemas.xmlsoap.org/soap/encoding/"; /* use SOAP encoding style */
	soap_serializeheader(soap);
	soap_serialize_ns1__div(soap, &soap_tmp_ns1__div);
	if (soap_begin_count(soap))
		return soap->error;
	if ((soap->mode & SOAP_IO_LENGTH))
	{	if (soap_envelope_begin_out(soap)
		 || soap_putheader(soap)
		 || soap_body_begin_out(soap)
		 || soap_put_ns1__div(soap, &soap_tmp_ns1__div, "ns1:div", "")
		 || soap_body_end_out(soap)
		 || soap_envelope_end_out(soap))
			 return soap->error;
	}
	if (soap_end_count(soap))
		return soap->error;
	if (soap_connect(soap, soap_endpoint, soap_action)
	 || soap_envelope_begin_out(soap)
	 || soap_putheader(soap)
	 || soap_body_begin_out(soap)
	 || soap_put_ns1__div(soap, &soap_tmp_ns1__div, "ns1:div", "")
	 || soap_body_end_out(soap)
	 || soap_envelope_end_out(soap)
	 || soap_end_send(soap))
		return soap_closesock(soap);
	return SOAP_OK;
}

SOAP_FMAC5 int SOAP_FMAC6 soap_recv_ns1__div(struct soap *soap, double *result)
{
	struct ns1__divResponse *soap_tmp_ns1__divResponse;
	if (!result)
		return soap_closesock(soap);
	soap_default_double(soap, result);
	if (soap_begin_recv(soap)
	 || soap_envelope_begin_in(soap)
	 || soap_recv_header(soap)
	 || soap_body_begin_in(soap))
		return soap_closesock(soap);
	if (soap_recv_fault(soap, 1))
		return soap->error;
	soap_tmp_ns1__divResponse = soap_get_ns1__divResponse(soap, NULL, "", NULL);
	if (!soap_tmp_ns1__divResponse || soap->error)
		return soap_recv_fault(soap, 0);
	if (soap_body_end_in(soap)
	 || soap_envelope_end_in(soap)
	 || soap_end_recv(soap))
		return soap_closesock(soap);
	if (result && soap_tmp_ns1__divResponse->result)
		*result = *soap_tmp_ns1__divResponse->result;
	return soap_closesock(soap);
}

#ifdef __cplusplus
}
#endif

#if defined(__BORLANDC__)
#pragma option pop
#pragma option pop
#endif

/* End of soapClient.c */
