#pragma once

#define ASN1_RELEASE2_PREFIX Vanetza_ITS2_
#define ASN1_RELEASE1_PREFIX

#define ASN1_CONCAT(x, y) ASN1_CONCAT_AGAIN(x, y)
#define ASN1_CONCAT_AGAIN(x, y) x ## y

#define ASN1_RELEASE1_NAME(name) ASN1_CONCAT(ASN1_RELEASE1_PREFIX, name)
#define ASN1_RELEASE2_NAME(name) ASN1_CONCAT(ASN1_RELEASE2_PREFIX, name)

/**
 * Prepend code generation prefix to an ASN.1 name or type.
 */
#define ASN1_PREFIXED(name) ASN1_CONCAT(ASN1_PREFIX, name)

/**
 * Check that enum name has equal value in both releases. 
 */
#define ASSERT_EQUAL_ENUM(name) \
    static_assert(int(ASN1_RELEASE1_NAME(name)) == int(ASN1_RELEASE2_NAME(name)), \
    #name " mismatch between release 1 and 2");

/**
 * Check that types are equal in both releases
 */
#define ASSERT_EQUAL_TYPE(name) \
    static_assert(std::is_same<ASN1_RELEASE1_NAME(name), ASN1_RELEASE2_NAME(name)>::value, \
    #name " type mismatch between release 1 and 2");
