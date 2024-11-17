#!/bin/bash

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🔍 Verificando SEVO..."

# Verificar firma GPG del binario
echo -e "${YELLOW}📦 Verificando firma del binario...${NC}"
if gpg --verify sevo-bin.asc sevo-bin 2>/dev/null; then
    echo -e "${GREEN}✓ Firma del binario válida${NC}"
else
    echo -e "${RED}✗ Error: Firma del binario inválida${NC}"
    exit 1
fi

# Verificar firma del archivo SHA3
echo -e "${YELLOW}🔐 Verificando firma del archivo SHA3...${NC}"
if gpg --verify sevo-bin.sha3-256.asc sevo-bin.sha3-256 2>/dev/null; then
    echo -e "${GREEN}✓ Firma del SHA3 válida${NC}"
else
    echo -e "${RED}✗ Error: Firma del SHA3 inválida${NC}"
    exit 1
fi

# Verificar suma SHA3-256
echo -e "${YELLOW}🔍 Verificando suma SHA3-256...${NC}"
STORED_HASH=$(cat sevo-bin.sha3-256)
CALCULATED_HASH=$(rhash --sha3-256 sevo-bin)
if [ "$STORED_HASH" = "$CALCULATED_HASH" ]; then
    echo -e "${GREEN}✓ Suma SHA3-256 válida${NC}"
else
    echo -e "${RED}✗ Error: Suma SHA3-256 inválida${NC}"
    echo -e "Esperado: $STORED_HASH"
    echo -e "Calculado: $CALCULATED_HASH"
    exit 1
fi

echo -e "${GREEN}✅ Verificación completada exitosamente${NC}"
