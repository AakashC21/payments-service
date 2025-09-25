#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🧪 Running Tests${NC}"

# Run tests
echo -e "${YELLOW}🔍 Running unit tests...${NC}"
./mvnw test

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed${NC}"
else
    echo -e "${RED}❌ Tests failed${NC}"
    exit 1
fi

# Generate coverage report
echo -e "${YELLOW}📊 Generating coverage report...${NC}"
./mvnw jacoco:report

echo -e "${GREEN}📈 Coverage report generated at: target/site/jacoco/index.html${NC}"

