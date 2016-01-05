#pragma once

#define XC3_LOG_SIGNATURE1 0x6368784C // Lxhc
#define XC3_LOG_SIGNATURE2 0x7A784C6D // mLxz

#define XC3_LOG_S1 "@#we$ppAz~?xqt"

typedef struct _XC3_LOG_CTX
{
	unsigned char _byte[0x100];
	unsigned long _100;
	unsigned long _104;

	void init(const char *key, int size)
	{
		unsigned char a;

		for (int i = 0; i < sizeof(_byte); i++)
			_byte[i] = i;

		for (int i = 0, j = 0; i < sizeof(_byte); i++)
		{
			a = _byte[i];
			j = key[i % size] + _byte[i] + j & 0xFF;
			_byte[i] = _byte[j];
			_byte[j] = a;
		}

		_100 = 0;
		_104 = 0;
	}

	unsigned char calc()
	{
		unsigned char a, b;

		_100 = _100 + 1 & 0xFF;

		a = _byte[_100] + _104 & 0xFF;
		_104 = a;
		b = _byte[a];

		_byte[a] = _byte[_100];
		_byte[_100] = b;

		return _byte[(_byte[_104] + b) & 0xFF];
	}
} XC3_LOG_CTX, *PXC3_LOG_CTX, *LPXC3_LOG_CTX;

typedef struct _XC3_LOG_TAILS
{
	unsigned long signature;
	unsigned long position;
	unsigned long index;
} XC3_LOG_TAILS, *PXC3_LOG_TAILS, *LPXC3_LOG_TAILS;

typedef struct _XC3_LOG_BUFFER
{
	unsigned long signature;
	unsigned short size;
	unsigned short type;
	// 8
	unsigned char key[16];
	char name[16];
	__time32_t unix_time;
	unsigned long _2C;
	unsigned long _30;
	unsigned long _34;
	unsigned long errorcode;	// errorcode?
	unsigned long _3C;
	unsigned long _40;
	char buffer[0xF0];

	// 308bytes.
} XC3_LOG_BUFFER, *PXC3_LOG_BUFFER, *LPXC3_LOG_BUFFER;