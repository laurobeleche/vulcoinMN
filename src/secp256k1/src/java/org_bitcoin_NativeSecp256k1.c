#include "org_bitcoin_NativeVlcp256k1.h"
#include "include/vlcp256k1.h"

JNIEXPORT jint JNICALL Java_org_bitcoin_NativeVlcp256k1_vlcp256k1_1ecdsa_1verify
  (JNIEnv* env, jclass classObject, jobject byteBufferObject)
{
	unsigned char* data = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
	int sigLen = *((int*)(data + 32));
	int pubLen = *((int*)(data + 32 + 4));

	return vlcp256k1_ecdsa_verify(data, 32, data+32+8, sigLen, data+32+8+sigLen, pubLen);
}

static void __javavlcp256k1_attach(void) __attribute__((constructor));
static void __javavlcp256k1_detach(void) __attribute__((destructor));

static void __javavlcp256k1_attach(void) {
	vlcp256k1_start(VLCP256K1_START_VERIFY);
}

static void __javavlcp256k1_detach(void) {
	vlcp256k1_stop();
}
