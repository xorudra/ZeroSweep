-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ScanStageType" ADD VALUE 'CONTENT_DISCOVERY';
ALTER TYPE "ScanStageType" ADD VALUE 'WEB_SURFACE_NORMALIZATION';

-- AlterTable
ALTER TABLE "Endpoint" ADD COLUMN     "classification" TEXT,
ADD COLUMN     "contentLength" INTEGER,
ADD COLUMN     "contentType" TEXT,
ADD COLUMN     "endpointType" TEXT NOT NULL DEFAULT 'UNKNOWN',
ADD COLUMN     "redirectLocation" TEXT,
ADD COLUMN     "sources" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "title" TEXT;

-- CreateTable
CREATE TABLE "EndpointParameter" (
    "id" TEXT NOT NULL,
    "endpointId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "location" TEXT NOT NULL DEFAULT 'QUERY',
    "sources" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "confidence" DOUBLE PRECISION,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EndpointParameter_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EndpointForm" (
    "id" TEXT NOT NULL,
    "endpointId" TEXT NOT NULL,
    "method" TEXT NOT NULL DEFAULT 'GET',
    "fieldNames" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "encodingType" TEXT,
    "source" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EndpointForm_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Wordlist" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "category" TEXT NOT NULL,
    "storageLocation" TEXT NOT NULL,
    "checksum" TEXT NOT NULL,
    "entryCount" INTEGER NOT NULL DEFAULT 0,
    "sizeBytes" INTEGER NOT NULL DEFAULT 0,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "version" TEXT,
    "profiles" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "technologies" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Wordlist_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "EndpointParameter_endpointId_idx" ON "EndpointParameter"("endpointId");

-- CreateIndex
CREATE UNIQUE INDEX "EndpointParameter_endpointId_name_location_key" ON "EndpointParameter"("endpointId", "name", "location");

-- CreateIndex
CREATE INDEX "EndpointForm_endpointId_idx" ON "EndpointForm"("endpointId");

-- CreateIndex
CREATE UNIQUE INDEX "Wordlist_name_key" ON "Wordlist"("name");

-- AddForeignKey
ALTER TABLE "EndpointParameter" ADD CONSTRAINT "EndpointParameter_endpointId_fkey" FOREIGN KEY ("endpointId") REFERENCES "Endpoint"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EndpointForm" ADD CONSTRAINT "EndpointForm_endpointId_fkey" FOREIGN KEY ("endpointId") REFERENCES "Endpoint"("id") ON DELETE CASCADE ON UPDATE CASCADE;

