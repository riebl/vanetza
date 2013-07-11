ASN1C?=asn1c
GEN_DIR=gen
ASN1C_ARGS=-fcompound-names -Werror -gen-PER -pdu=all

all: ${GEN_DIR} cdd_ts102894-2v1.1.1.asn1 cam_en302637-2v1.3.0.asn1 denm_en302637-3v1.2.0.asn1
	cd ${GEN_DIR} && ${ASN1C} ${ASN1C_ARGS} $(addprefix ../,$(filter-out $<,$^))

${GEN_DIR}:
	mkdir -p ${GEN_DIR}

clean:
	rm -rf ${GEN_DIR}

