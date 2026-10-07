-- AlterTable
ALTER TABLE "Asset" ADD COLUMN     "discoveredByScanId" TEXT,
ADD COLUMN     "httpStatus" INTEGER,
ADD COLUMN     "sources" TEXT[] DEFAULT ARRAY[]::TEXT[];

-- AlterTable
ALTER TABLE "Endpoint" ADD COLUMN     "parameterNames" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "scopeStatus" TEXT NOT NULL DEFAULT 'IN_SCOPE',
ADD COLUMN     "source" TEXT;

-- AlterTable
ALTER TABLE "Technology" ADD COLUMN     "confidence" DOUBLE PRECISION,
ADD COLUMN     "source" TEXT;

