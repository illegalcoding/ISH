#include "Request.h"
size_t SerializeRequest(char** Buffer, HTRequest* Request) {
	/* Calculate size of Buffer */	
	size_t NumHeaders = Request->NumHeaders;
	size_t RLMethodLength = strlen(Request->RequestLine.Method);
	size_t RLURILength = strlen(Request->RequestLine.URI);
	size_t RLVersionLength = strlen(Request->RequestLine.Version);
	size_t HFieldLengths[NumHeaders];
	size_t HValueLengths[NumHeaders];
	/* This is for all the spaces and terminators and such */
	/* We need:
	 * A colon in each Header
	 * A space in each Header
	 * A space after the Method in the RequestLine
	 * A space after the URI in the Method
	 * We also need a CRLF after the RequestLine
	 * And a CRLF after each Header
	 * And another 2 CRLFs at the end
	 * In total that should be (2*NumHeaders)+1+1+2+(2*NumHeaders)+2+2
	 */
	size_t AdditionalLength = (2*NumHeaders)+1+1+2+(2*NumHeaders)+2+2;
	/* fprintf(stderr,"AdditionalLength: %lu\n",AdditionalLength); */	
	size_t BufferLength = RLMethodLength+RLURILength+RLVersionLength+AdditionalLength;
	for(int i = 0; i<NumHeaders; i++) {
		HTRequestHeader Header = Request->Headers[i];
		size_t FieldLength = strlen(Header.Field);
		size_t ValueLength = strlen(Header.Value);
		BufferLength += FieldLength;
		BufferLength += ValueLength;
		HFieldLengths[i] = FieldLength;
		/* fprintf(stderr,"Header %d: Field Length %lu\n", i, FieldLength); */
		HValueLengths[i] = ValueLength;
		/* fprintf(stderr,"Header %d: Value Length %lu\n", i, ValueLength); */
	}
	/* fprintf(stderr,"BufferLength = %lu\n",BufferLength); */
	*Buffer = malloc(BufferLength+1);
	memset(*Buffer,0,BufferLength+1);
	/* fprintf(stderr,"Buffer allocated to %p\n",*Buffer); */
	/* Assemble Buffer */
	/* POST request consists of:
	 * RequestLine CRLF Header CRLF
	 * 
	 * RequestLine consists of:
	 * Method SP URI SP Version
	 *
	 * Header consits of:
	 * Field COLON SP Value
	 */
	size_t DataWritten = 0;

	/* Write RequestLine */

	/* Write method */
	strncpy((*Buffer)+DataWritten, Request->RequestLine.Method, RLMethodLength);
	DataWritten += RLMethodLength;

	/* Write space */
	strncpy((*Buffer)+DataWritten, " ", 1);
	DataWritten += 1;

	/* Write URI */
	strncpy((*Buffer)+DataWritten,Request->RequestLine.URI, RLURILength);	
	DataWritten += RLURILength;
	
	/* Write space */
	strncpy((*Buffer)+DataWritten," ", 1);
	DataWritten += 1;

	/* Write version */
	strncpy((*Buffer)+DataWritten, Request->RequestLine.Version, RLVersionLength);
	DataWritten += RLVersionLength;
	
	/* We've done the RequestLine */

	/* Write CRLF */
	strncpy((*Buffer)+DataWritten, "\r\n", 2);
	DataWritten += 2;

	/* Write Headers */
	
	for(int i = 0; i<NumHeaders; i++) {
		const char* Field = Request->Headers[i].Field;
		const size_t HFieldLength = HFieldLengths[i];
		const char* Value = Request->Headers[i].Value;
		const size_t HValueLength = HValueLengths[i];
		strncpy((*Buffer)+DataWritten, Field, HFieldLength);
		DataWritten += HFieldLength;
		/* Write COLON SP */
		strncpy((*Buffer)+DataWritten,": ", 2);
		DataWritten += 2;
		strncpy((*Buffer)+DataWritten, Value, HValueLength);
		DataWritten += HValueLength;
		/* Write CRLF */
		strncpy((*Buffer)+DataWritten, "\r\n", 2);
		DataWritten += 2;
	}

	/* Write final 2 CRLF */
	strncpy((*Buffer)+DataWritten, "\r\n", 2);
	DataWritten += 2;
	strncpy((*Buffer)+DataWritten, "\r\n", 2);
	DataWritten += 2;

	if(DataWritten != BufferLength) {
		fprintf(stderr, "Warning: DataWritten != BufferLength\n");
		fprintf(stderr,"DataWritten: %lu, BufferLength: %lu\n",DataWritten,BufferLength);
	}
	/* fprintf(stderr,"Buffer: %s\n",*Buffer); */
	/* fprintf(stderr,"strlen(*Buffer): %lu\n",strlen(*Buffer)); */
	return BufferLength;
}
