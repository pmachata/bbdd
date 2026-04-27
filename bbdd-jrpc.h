/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <json-c/json_object.h>

struct bbdd_sock;

enum bbdd_jrpc_e {
	bbdd_jrpc_e_capacity = -1,
	bbdd_jrpc_e_reg_process_emad = -2,

	bbdd_jrpc_e_inv_request = -32600,
	bbdd_jrpc_e_method_nf = -32601,
	bbdd_jrpc_e_inv_params = -32602,
	bbdd_jrpc_e_int_error = -32603,
};

struct bbdd_jrpc_policy {
	const char *key;
	enum json_type type;
	bool any_type;
	bool nullable;	/* Either the given type, or nil. */
	bool required;
};

struct json_object *bbdd_jrpc_new_object(struct json_object *id);
struct json_object *bbdd_jrpc_new_request(int id, const char *method);
struct json_object *bbdd_jrpc_new_error(struct json_object *id,
					enum bbdd_jrpc_e code,
					const char *message,
					const char *data);
struct json_object *bbdd_jrpc_new_error_data(struct json_object *id,
					     enum bbdd_jrpc_e code,
					     const char *message,
					     struct json_object *data);
struct json_object *bbdd_jrpc_new_error_inv_request(const char *data);
struct json_object *bbdd_jrpc_new_error_method_nf(struct json_object *id,
						  const char *method);
struct json_object *bbdd_jrpc_new_error_inv_params(struct json_object *id,
						   const char *data);
struct json_object *bbdd_jrpc_new_error_int_error(struct json_object *id,
						  const char *data);

int bbdd_jrpc_dissect(struct json_object *obj,
		      struct bbdd_jrpc_policy policy[],
		      bool seen[],
		      struct json_object *values[],
		      size_t policy_size,
		      char **error);

int bbdd_jrpc_dissect_request(struct json_object *obj,
			      struct json_object **id,
			      const char **method,
			      struct json_object **params,
			      char **error);
int bbdd_jrpc_dissect_response(struct json_object *obj,
			       struct json_object **id,
			       struct json_object **result,
			       bool *is_error,
			       char **error);
int bbdd_jrpc_dissect_error(struct json_object *obj,
			    int64_t *code,
			    const char **message,
			    struct json_object **data,
			    char **error);
int bbdd_jrpc_dissect_params_empty(struct json_object *obj,
				   char **error);
int bbdd_jrpc_validate_array(struct json_object *obj, enum json_type elm_type,
			     char **error);

int bbdd_jrpc_get_uint32(struct json_object *obj, uint32_t *ret, char **error);
int bbdd_jrpc_get_uint32_non0(struct json_object *obj, uint32_t *ret,
			      char **error);
int bbdd_jrpc_get_uint8(struct json_object *obj, uint8_t *ret, char **error);
int bbdd_jrpc_strcpy(size_t buf_len;
		     struct json_object *obj, char buf[buf_len], size_t buf_len,
		     char **error);

int bbdd_jrpc_append_str(struct json_object *params_obj,
			 const char *name, const char *value);
int bbdd_jrpc_append_int(struct json_object *params_obj,
			 const char *name, int64_t value);
int bbdd_jrpc_append_bool(struct json_object *params_obj,
			  const char *name, bool value);
int bbdd_jrpc_append_uint64(struct json_object *params_obj,
			    const char *name, uint64_t value);
int bbdd_jrpc_append_obj(struct json_object *params_obj,
			 const char *name,
			 struct json_object **objp);
