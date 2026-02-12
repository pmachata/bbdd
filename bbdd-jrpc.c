// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#define _GNU_SOURCE

#include "bbdd-jrpc.h"

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <json-c/json_object.h>
#include <json-c/json_object_iterator.h>
#include <json-c/json_util.h>

__attribute__((format(printf, 2, 3)))
int bbdd_jrpc_fmterr(char **strp, const char *fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = vasprintf(strp, fmt, ap);
	va_end(ap);

	if (rc < 0)
		*strp = NULL;
	return rc;
}

static int __bbdd_jrpc_object_add(struct json_object *obj,
				  const char *key,
				  struct json_object *val_obj)
{
	int rc;

	if (val_obj == NULL)
		return -1;

	rc = json_object_object_add(obj, key, val_obj);
	if (rc != 0)
		goto err_put_val_obj;

	return 0;

err_put_val_obj:
	json_object_put(val_obj);
	return -1;
}

int bbdd_jrpc_object_add_int(struct json_object *obj,
			     const char *key, int64_t val)
{
	return __bbdd_jrpc_object_add(obj, key, json_object_new_int64(val));
}

int bbdd_jrpc_object_add_str(struct json_object *obj,
			     const char *key, const char *str)
{
	return __bbdd_jrpc_object_add(obj, key, json_object_new_string(str));
}

int bbdd_jrpc_object_add_bool(struct json_object *obj,
			      const char *key, bool val)
{
	return __bbdd_jrpc_object_add(obj, key, json_object_new_boolean(val));
}

static int bbdd_jrpc_object_add_error(struct json_object *obj,
				      int code, const char *message,
				      struct json_object *data)
{
	struct json_object *err_obj;
	int rc;

	err_obj = json_object_new_object();
	if (err_obj == NULL)
		return -1;

	rc = bbdd_jrpc_object_add_int(err_obj, "code", code);
	if (rc != 0)
		goto err_put_err_obj;

	rc = bbdd_jrpc_object_add_str(err_obj, "message", message);
	if (rc != 0)
		goto err_put_err_obj;

	if (data != NULL) {
		/* Allow this to fail, the error object is valid without it. */
		rc = json_object_object_add(err_obj, "data", data);
		if (rc == 0)
			json_object_get(data);
	}

	rc = json_object_object_add(obj, "error", err_obj);
	if (rc != 0)
		goto err_put_err_obj;

	return 0;

err_put_err_obj:
	json_object_put(err_obj);
	return -1;
}

struct json_object *bbdd_jrpc_new_object(struct json_object *id)
{
	struct json_object *obj;
	int rc;

	obj = json_object_new_object();
	if (obj == NULL)
		return NULL;

	rc = bbdd_jrpc_object_add_str(obj, "jsonrpc", "2.0");
	if (rc != 0)
		goto err_put_obj;

	rc = json_object_object_add(obj, "id", id);
	if (rc != 0)
		goto err_put_obj;
	json_object_get(id);

	return obj;

err_put_obj:
	json_object_put(obj);
	return NULL;
}

struct json_object *bbdd_jrpc_new_request(int id, const char *method)
{
	struct json_object *request;
	struct json_object *id_obj;
	int rc;

	id_obj = json_object_new_int(id);
	if (id_obj == NULL) {
		fprintf(stderr, "Failed to allocate an ID object.\n");
		return NULL;
	}

	request = bbdd_jrpc_new_object(id_obj);
	if (request == NULL) {
		fprintf(stderr, "Failed to allocate a request object.\n");
		goto put_id;
	}

	rc = bbdd_jrpc_object_add_str(request, "method", method);
	if (rc != 0) {
		fprintf(stderr, "Failed to form a request object.\n");
		goto put_request;
	}

	goto put_id;

put_request:
	json_object_put(request);
put_id:
	json_object_put(id_obj);
	return request;
}

struct json_object *bbdd_jrpc_new_error_data(struct json_object *id,
					     enum bbdd_jrpc_e code,
					     const char *message,
					     struct json_object *data)
{
	struct json_object *obj;
	int rc;

	obj = bbdd_jrpc_new_object(id);
	if (obj == NULL)
		return NULL;

	rc = bbdd_jrpc_object_add_error(obj, code, message, data);
	if (rc != 0)
		goto err_put_obj;

	return obj;

err_put_obj:
	json_object_put(obj);
	return NULL;
}

struct json_object *bbdd_jrpc_new_error(struct json_object *id,
					enum bbdd_jrpc_e code,
					const char *message,
					const char *data)
{
	struct json_object *data_obj;
	struct json_object *obj;

	/* Allow this to fail, the error object is valid without it. */
	data_obj = json_object_new_string(data);

	obj = bbdd_jrpc_new_error_data(id, code, message, data_obj);

	json_object_put(data_obj);
	return obj;
}

struct json_object *bbdd_jrpc_new_error_inv_request(const char *data)
{
	return bbdd_jrpc_new_error(NULL, bbdd_jrpc_e_inv_request,
				   "Invalid Request", data);
}

struct json_object *bbdd_jrpc_new_error_method_nf(struct json_object *id,
						  const char *method)
{
	return bbdd_jrpc_new_error(id, bbdd_jrpc_e_method_nf,
				   "Method not found", method);
}

struct json_object *bbdd_jrpc_new_error_inv_params(struct json_object *id,
						   const char *data)
{
	return bbdd_jrpc_new_error(id, bbdd_jrpc_e_inv_params,
				   "Invalid params", data);
}

struct json_object *bbdd_jrpc_new_error_int_error(struct json_object *id,
						  const char *data)
{
	return bbdd_jrpc_new_error(id, bbdd_jrpc_e_int_error,
				   "Internal error", data);
}

int bbdd_jrpc_dissect(struct json_object *obj,
		      struct bbdd_jrpc_policy policy[],
		      bool seen[],
		      struct json_object *values[],
		      size_t policy_size,
		      char **error)
{
	{
		enum json_type type = json_object_get_type(obj);

		if (type != json_type_object) {
			bbdd_jrpc_fmterr(error, "Value expected to be an object, but is %s",
					 json_type_to_name(type));
			return -1;
		}
	}

	for (struct json_object_iterator it = json_object_iter_begin(obj),
					 et = json_object_iter_end(obj);
	     !json_object_iter_equal(&it, &et);
	     json_object_iter_next(&it)) {
		struct json_object *val = json_object_iter_peek_value(&it);
		const char *key = json_object_iter_peek_name(&it);
		bool found = false;

		for (size_t i = 0; i < policy_size; i++) {
			struct bbdd_jrpc_policy *pol = &policy[i];

			if (strcmp(key, pol->key) == 0) {
				enum json_type type = json_object_get_type(val);

				if (!pol->any_type && pol->type != type) {
					bbdd_jrpc_fmterr(error, "The member %s is expected to be a %s, but is %s",
						    key,
						    json_type_to_name(pol->type),
						    json_type_to_name(type));
					return -1;
				}

				if (seen[i]) {
					bbdd_jrpc_fmterr(error, "Duplicate member %s",
							 key);
					return -1;
				}

				seen[i] = true;
				values[i] = val;
				found = true;
				break;
			}
		}

		if (!found) {
			bbdd_jrpc_fmterr(error, "The member %s is not expected",
					 key);
			return -1;
		}
	}

	for (size_t i = 0; i < policy_size; i++) {
		struct bbdd_jrpc_policy *pol = &policy[i];

		if (!seen[i] && pol->required) {
			bbdd_jrpc_fmterr(error, "Required member %s not present",
					 pol->key);
			return -1;
		}
	}

	return 0;
}

static bool bbdd_jrpc_validate_version(struct json_object *ver_obj,
				       char **error)
{
	const char *ver;

	assert(json_object_get_type(ver_obj) == json_type_string);
	ver = json_object_get_string(ver_obj);
	if (strcmp(ver, "2.0") != 0) {
		bbdd_jrpc_fmterr(error, "Unsupported jsonrpc version: %s", ver);
		return false;
	}

	return true;
}

int bbdd_jrpc_dissect_request(struct json_object *obj,
			      struct json_object **id,
			      const char **method,
			      struct json_object **params,
			      char **error)
{
	enum {
		pol_jsonrpc,
		pol_id,
		pol_method,
		pol_params,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_jsonrpc] = { .key = "jsonrpc", .type = json_type_string,
				  .required = true },
		[pol_id] =      { .key = "id", .any_type = true,
				  .required = true },
		[pol_method] =  { .key = "method", .type = json_type_string,
				  .required = true },
		[pol_params] =  { .key = "params", .any_type = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int err;

	err = bbdd_jrpc_dissect(obj, policy, seen, values,
				ARRAY_SIZE(policy), error);
	if (err)
		return err;

	if (!bbdd_jrpc_validate_version(values[pol_jsonrpc], error))
		return -1;

	*id = values[pol_id];
	*method = json_object_get_string(values[pol_method]);
	*params = values[pol_params];
	return 0;
}

int bbdd_jrpc_dissect_response(struct json_object *obj,
			       struct json_object **id,
			       struct json_object **result,
			       bool *is_error,
			       char **error)
{
	enum {
		pol_jsonrpc,
		pol_id,
		pol_result,
		pol_error,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_jsonrpc] = { .key = "jsonrpc", .type = json_type_string,
				  .required = true },
		[pol_id] =      { .key = "id", .any_type = true,
				  .required = true },
		[pol_error] =   { .key = "error", .type = json_type_object },
		[pol_result] =  { .key = "result", .any_type = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int err;

	err = bbdd_jrpc_dissect(obj, policy, seen, values,
				ARRAY_SIZE(policy), error);
	if (err)
		return err;

	if (!bbdd_jrpc_validate_version(values[pol_jsonrpc], error))
		return -1;

	if (seen[pol_error] && seen[pol_result]) {
		bbdd_jrpc_fmterr(error, "Both error and result present in jsonrpc response");
		return -1;
	} else if (!seen[pol_error] && !seen[pol_result]) {
		bbdd_jrpc_fmterr(error, "Neither error nor result present in jsonrpc response");
		return -1;
	}

	*id = values[pol_id];
	*result = seen[pol_result] ? values[pol_result] : values[pol_error];
	*is_error = seen[pol_error];
	return 0;
}

int bbdd_jrpc_dissect_error(struct json_object *obj,
			    int64_t *code,
			    const char **message,
			    struct json_object **data,
			    char **error)
{
	enum {
		pol_code,
		pol_message,
		pol_data,
	};
	struct bbdd_jrpc_policy policy[] = {
		[pol_code] =    { .key = "code", .type = json_type_int,
				  .required = true },
		[pol_message] = { .key = "message", .type = json_type_string,
				  .required = true },
		[pol_data] =    { .key = "data", .any_type = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int err;

	err = bbdd_jrpc_dissect(obj, policy, seen, values,
				ARRAY_SIZE(policy), error);
	if (err)
		return err;

	*code = json_object_get_int64(values[pol_code]);
	*message = json_object_get_string(values[pol_message]);
	*data = values[pol_data];
	return 0;
}

int bbdd_jrpc_dissect_params_empty(struct json_object *obj, char **error)
{
	if (obj == NULL)
		return 0;
	return bbdd_jrpc_dissect(obj, NULL, NULL, NULL, 0, error);
}

static int bbdd_jrpc_get_uint(struct json_object *obj, uint32_t *ret,
			      uint32_t max, char **error)
{
	int64_t v;

	errno = 0;
	v = json_object_get_int64(obj);
	if (errno) {
		bbdd_jrpc_fmterr(error, "Value expected to be an integer: %m");
		return -1;
	}

	if (v < 0 || v > (int64_t) max) {
		bbdd_jrpc_fmterr(error, "Expected uint with maximum value `%ud', got %" PRIi64,
				 max, v);
		return -1;
	}

	*ret = (uint32_t) v;
	return 0;
}

int bbdd_jrpc_get_uint32(struct json_object *obj, uint32_t *ret, char **error)
{
	return bbdd_jrpc_get_uint(obj, ret, UINT32_MAX, error);
}

int bbdd_jrpc_get_uint32_non0(struct json_object *obj, uint32_t *ret,
			      char **error)
{
	if (bbdd_jrpc_get_uint32(obj, ret, error) < 0)
		return -1;
	if (*ret == 0) {
		bbdd_jrpc_fmterr(error, "Expected non-zero uint32, got 0");
		return -1;
	}
	return 0;
}

int bbdd_jrpc_get_uint8(struct json_object *obj, uint8_t *ret, char **error)
{
	uint32_t value;
	int rc;

	rc = bbdd_jrpc_get_uint(obj, &value, UINT8_MAX, error);
	if (rc != 0)
		return rc;

	*ret = (uint8_t) value;
	return 0;
}

int bbdd_jrpc_strcpy(size_t buf_len;
		     struct json_object *obj, char buf[buf_len], size_t buf_len,
		     char **error)
{
	const char *str;

	str = json_object_get_string(obj);
	if (strlen(str) >= buf_len) {
		bbdd_jrpc_fmterr(error, "String `%s' too long: %zd >= %zd",
				 str, strlen(str), buf_len);
		return -1;
	}

	strcpy(buf, str);
	return 0;
}
