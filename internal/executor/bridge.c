/* cgo entry point: build the same C implementation as an in-process library. */
#define EXECUTOR_LIBRARY 1
#include "../../executor/c/executor_impl.inc"
