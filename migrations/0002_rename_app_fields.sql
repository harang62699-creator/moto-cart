-- applications 테이블 필드명 변경 및 신규 컬럼 추가
-- brand → importer, model → cert_year, model_year → displacement, family_code 신규

ALTER TABLE applications RENAME COLUMN brand TO importer;
ALTER TABLE applications RENAME COLUMN model TO cert_year;
ALTER TABLE applications RENAME COLUMN model_year TO displacement;
ALTER TABLE applications ADD COLUMN family_code TEXT DEFAULT '';
ALTER TABLE applications ADD COLUMN lang TEXT DEFAULT 'ko';
