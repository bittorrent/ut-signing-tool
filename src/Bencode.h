#ifndef BENCODE_H
#define BENCODE_H

#include <map>
#include <vector>
#include <stdint.h>

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

// XXX: Copying or assigning objects invalidates the original. 
//      This also breaks the constness of the original.

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
		int64_t intValue(int64_t def = 0);
		void setIntValue(int64_t val);

		// for dicts
		BencodeObject* valueForKey(const char* key);
		int64_t intValueForKey(const char* key, int64_t def = 0);
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
		const char* stringValue(const char* def = "");
		void setByteStringValue(const void* val, size_t len, BencodeMode mode = BencodeModeNondestructive);

		size_t serializedSize();
		size_t serialize(void* dest, size_t maxlen);

	private:
		BencodeType _type;
		BencodeMode _mode;
		
		int64_t _intValue;

		size_t _actualLength;

		BencodeListStorage* _listValue;
		BencodeDictStorage* _dictValue;
		
		void* _byteStringPtr;
		size_t _byteStringSize;
		
		void* _mem;
		char* _stringValue;

		size_t _serializedSize;
		
		const char* _terminatedStringValue(const char* def, bool terminateInPlace = false);
};

#endif
