ASN1C?=asn1c
GEN_DIR=gen
ASN1C_ARGS=-fcompound-names -Werror -gen-PER -pdu=all

all: ${GEN_DIR} cam.asn1 denm.asn1
	cd ${GEN_DIR} && ${ASN1C} ${ASN1C_ARGS} $(addprefix ../,$(filter-out $<,$^))

${GEN_DIR}:
	mkdir -p ${GEN_DIR}

clean:
	rm -rf ${GEN_DIR}

