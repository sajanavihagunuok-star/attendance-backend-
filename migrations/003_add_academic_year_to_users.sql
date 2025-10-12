ALTER TABLE users
ADD COLUMN academic_year_id INTEGER REFERENCES academic_years(id) ON DELETE SET NULL;