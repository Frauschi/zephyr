# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.28.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(tls_socket_api_extension)

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)

if(${CONFIG_TLS_CREDENTIALS})
  generate_inc_file_for_target(
    app
    ${ZEPHYR_BASE}/samples/net/sockets/echo_server/src/ca.der
    ${gen_dir}/ca.inc
  )

  generate_inc_file_for_target(
    app
    ${ZEPHYR_BASE}/samples/net/sockets/echo_server/src/server.der
    ${gen_dir}/server.inc
  )

  generate_inc_file_for_target(
    app
    ${ZEPHYR_BASE}/samples/net/sockets/echo_server/src/server_privkey.der
    ${gen_dir}/server_privkey.inc
  )

  # we reuse the same certificate / private key for client
  # since it seems to be the only one that is signed by a ca
  generate_inc_file_for_target(
    app
    ${ZEPHYR_BASE}/samples/net/sockets/echo_server/src/server.der
    ${gen_dir}/client.inc
  )

  generate_inc_file_for_target(
    app
    ${ZEPHYR_BASE}/samples/net/sockets/echo_server/src/server_privkey.der
    ${gen_dir}/client_privkey.inc
  )

  if(CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_STAPLING OR CONFIG_WOLFSSL_CRYPTO_CB)
    foreach(f ocsp_ca ocsp_server ocsp_server_key ocsp_good)
      generate_inc_file_for_target(app ${CMAKE_CURRENT_SOURCE_DIR}/src/ocsp/${f}.der
        ${gen_dir}/${f}.inc)
    endforeach()
  endif()

  if(CONFIG_WOLFSSL)
    foreach(f client_a_chain client_b client_key)
      generate_inc_file_for_target(app ${CMAKE_CURRENT_SOURCE_DIR}/src/chain_ca/${f}.der
        ${gen_dir}/${f}.inc)
    endforeach()
  endif()
endif()

FILE(GLOB app_sources src/*.c)
target_sources(app PRIVATE ${app_sources})
