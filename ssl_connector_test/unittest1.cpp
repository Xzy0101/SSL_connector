#include "stdafx.h"
#include "CppUnitTest.h"

#include "..\SSL_connector\ssl_connector.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace ssl_connector_test
{		
	TEST_CLASS(UnitTest1)
	{
	public:
		
		TEST_METHOD(Init)
		{
			// TODO: Your test code here
			Assert::IsNotNull(ssl_connector_init(stderr));
		}

		TEST_METHOD(connect)
		{
			ssl_connector* conn = ssl_connector_init(stderr);
			Assert::AreEqual(0, ssl_connector_connect(conn, "www.baidu.com", 443, stderr));
		}

		TEST_METHOD(listen)
		{
			FILE* errlog = NULL;
			fopen_s(&errlog, "err.log", "w");
			ssl_connector* conn = ssl_connector_init(errlog);
			Assert::AreEqual(0, ssl_connector_listen(conn, 55555, "key.pem", "cert.pem", errlog));
		}

	};
}