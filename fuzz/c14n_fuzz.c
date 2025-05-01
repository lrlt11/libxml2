#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/c14n.h>
#include <libxml/xmlmemory.h>

#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if(!data || size == 0) {
        return 0;
    }

    // convert the data input into a xml c string
    char *xml_string = malloc(size + 1); // + 1 for null terminator
    if (!xml_string) {
        return 0; 
    }
    memcpy(xml_string, data, size); 
    xml_string[size] = '\0'; 

    // parse the xml string
    xmlDocPtr xml_doc = xmlReadMemory(xml_string, size, "fuzz.xml", NULL, 0); 
    if (!xml_doc) {
        free(xml_string);
        return 0; 
    }
    xmlChar *canonicalized_xml = NULL; 
    xmlC14NDocDumpMemory(xml_doc, NULL, 0, NULL, 0, &canonicalized_xml);

    if (canonicalized_xml) xmlFree(canonicalized_xml);

    free(xml_string); 
    xmlFreeDoc(xml_doc);
    xmlCleanupParser(); 
    return 0;
}