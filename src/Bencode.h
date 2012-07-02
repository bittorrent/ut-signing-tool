#ifndef BENCODE_H
#define BENCODE_H

#include <map>
#include <vector>
#include <stdint.h>

typedef int64_t int64;

typedef enum {
	BencodeTypeInvalid,
	BencodeTypeByteString,
	BencodeTypeInteger,
	BencodeTypeList,
	BencodeTypeDictionary,
} BencodeType;

typedef enum {
	BencodeModeDestructive,
	BencodeModeNondestructive,
	BencodeModeCopy,
	BencodeModeAdopt,
} BencodeMode;

class BencodeObject;

typedef std::map<BencodeObject, BencodeObject> BencodeDictStorage;
typedef std::vector<BencodeObject> BencodeListStorage;

class BencodeObject {
	public:
		BencodeObject();
		BencodeObject(const BencodeType type);
		BencodeObject(const char* string, BencodeMode mode = BencodeModeNondestructive);
		BencodeObject(const void* data, size_t len, BencodeMode mode = BencodeModeNondestructive);
		BencodeObject(const BencodeObject& obj);
		~BencodeObject();

		bool operator> (const BencodeObject &obj) const;
		bool operator< (const BencodeObject &obj) const;
		bool operator>= (const BencodeObject &obj) const;
		bool operator<= (const BencodeObject &obj) const;
		BencodeObject& operator=(const BencodeObject &obj);

		BencodeType type();
		
		// for ints
		int64 intValue(int64 def = 0);
		void setIntValue(int64 val);

		// for dicts
		BencodeObject* valueForKey(const char* key);
		int64 intValueForKey(const char* key, int64 def = 0);
		const char* stringValueForKey(const char* key, const char* def = "");
		const void* byteStringValueForKey(const char* key, size_t* len);
		BencodeDictStorage* dictValue();
		BencodeObject* setValueForKey(const char* key, BencodeObject* val);
		void removeValueForKey(const char* key);

		// for lists
		BencodeObject* valueAtIndex(unsigned int i);
		BencodeListStorage* listValue();

		// for dicts and lists
		unsigned int count();

		// for byte strings
		const void* byteStringValue(size_t* len);
		// the canTerminate parameter is meant only to be used by stringValueForKey
		const char* stringValue(const char* def = "", bool canTerminate = false);
		void setByteStringValue(const void* val, size_t len, BencodeMode mode = BencodeModeNondestructive);

		size_t serializedSize();
		size_t serialize(void* dest, size_t maxlen);

	private:
		BencodeType _type;
		BencodeMode _mode;
		
		int64 _intValue;

		size_t _actualLength;

		BencodeListStorage* _listValue;
		BencodeDictStorage* _dictValue;
		
		void* _byteStringPtr;
		size_t _byteStringSize;
		
		void* _mem;
		char* _stringValue;

		size_t _serializedSize;
};

#endif