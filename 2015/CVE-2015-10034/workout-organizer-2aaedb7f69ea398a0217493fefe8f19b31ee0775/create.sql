CREATE TABLE exercises (
	exercise_id          serial  NOT NULL,
	exercise_name        varchar(100)  NOT NULL,
	description          text  ,
	movie_uri            varchar(200)  ,
	CONSTRAINT pk_exercises PRIMARY KEY ( exercise_id )
 );

CREATE TABLE gyms (
	gym_id               serial  NOT NULL,
	gym_name             varchar(100)  NOT NULL,
	city                 varchar(100)  NOT NULL,
	street               varchar(100)  NOT NULL,
	latitude             real  ,
	longitude            real  ,
	url                  varchar(300)  ,
	CONSTRAINT pk_gyms PRIMARY KEY ( gym_id )
 );

CREATE TABLE muscle_groups (
	muscle_name          varchar(100)  NOT NULL,
	image_path           varchar(255)  ,
	CONSTRAINT pk_muscle_groups PRIMARY KEY ( muscle_name )
 );

CREATE TABLE exercise_muscle_groups (
	exercise_id          integer  NOT NULL,
	muscle_name          varchar(100)  NOT NULL
 );

CREATE TABLE equipment (
  equipment_name       varchar(100)  NOT NULL,
  image_path           varchar(255)  ,
  CONSTRAINT pk_equipment PRIMARY KEY ( equipment_name )
 );

CREATE TABLE exercise_equipment (
  exercise_id          integer  NOT NULL,
  equipment_name       varchar(100)  NOT NULL
 );

CREATE INDEX idx_exercise_muscle_groups ON exercise_muscle_groups ( muscle_name );

CREATE INDEX idx_exercise_muscle_groups_0 ON exercise_muscle_groups ( exercise_id );

CREATE TABLE users (
	user_id              serial  NOT NULL,
	login                varchar(20)  NOT NULL,
	email                varchar(50)  NOT NULL,
	password_digest      char(40)  NOT NULL,
	first_name           varchar(100)  NOT NULL,
	last_name            varchar(100)  NOT NULL,
	height               integer  ,
	weight               numeric(5,2)  ,
	date_of_birth        date  ,
	CONSTRAINT pk_users PRIMARY KEY ( user_id ),
	CONSTRAINT unique_login UNIQUE ( login ) ,
	CONSTRAINT unique_mail UNIQUE ( email )
 );

ALTER TABLE users ADD CONSTRAINT height_chk CHECK ( height > 0 AND height < 300 );

ALTER TABLE users ADD CONSTRAINT weight_ckh CHECK ( weight > 0 );

CREATE TABLE workouts (
	workout_id           serial  NOT NULL,
	user_id              integer  NOT NULL,
	gym_id               integer  ,
	started_at           timestamp DEFAULT current_timestamp NOT NULL,
	finished_at          timestamp  NOT NULL,
	note                 varchar(300)  ,
	CONSTRAINT pk_workouts PRIMARY KEY ( workout_id )
 );

ALTER TABLE workouts ADD CONSTRAINT time_check CHECK ( started_at < finished_at );

CREATE INDEX idx_workouts ON workouts ( user_id );

CREATE INDEX idx_workouts_0 ON workouts ( gym_id );

CREATE TABLE exercise_ratings (
	user_id              integer  NOT NULL,
	exercise_id          integer  NOT NULL,
	rating               integer  NOT NULL,
	CONSTRAINT pk_exercises_ratings PRIMARY KEY ( user_id, exercise_id )
 );

ALTER TABLE exercise_ratings ADD CONSTRAINT rating_chk CHECK ( rating BETWEEN 1 AND 10 );

CREATE INDEX idx_exercises_ratings ON exercise_ratings ( user_id );

CREATE INDEX idx_exercises_ratings_0 ON exercise_ratings ( exercise_id );

CREATE TABLE friendships (
  first_user_id        integer  NOT NULL,
  second_user_id       integer  NOT NULL,
  CONSTRAINT unique_friendships_rel UNIQUE ( first_user_id, second_user_id )
 );

ALTER TABLE friendships ADD CONSTRAINT proper_rel_check CHECK ( first_user_id < second_user_id );

CREATE TABLE friendship_requests (
  first_user_id        integer  NOT NULL,
  second_user_id       integer  NOT NULL,
  CONSTRAINT unique_friendship_requests_rel UNIQUE ( first_user_id, second_user_id )
 );

CREATE TABLE gym_ratings (
	gym_id               integer  NOT NULL,
	user_id              integer  NOT NULL,
	rating               integer  NOT NULL,
	CONSTRAINT idx_gym_ratings PRIMARY KEY ( gym_id, user_id )
 );

ALTER TABLE gym_ratings ADD CONSTRAINT rating_chk CHECK ( rating BETWEEN 1 AND 10 );

CREATE TABLE likes (
  user_id              integer  NOT NULL,
  workout_id           integer  NOT NULL,
  CONSTRAINT idx_likes UNIQUE ( user_id, workout_id )
 );

CREATE TABLE comments (
  comment_id           serial  NOT NULL,
  user_id              integer  NOT NULL,
  workout_id           integer  NOT NULL,
  content              text,
  created_at           timestamp DEFAULT current_timestamp NOT NULL
 );

CREATE TABLE workout_entries (
	workout_id           integer  NOT NULL,
	exercise_id          integer  NOT NULL,
	set_count            integer  NOT NULL,
	reps_per_set         integer  ,
	weight               numeric(5,2)  ,
	CONSTRAINT idx_workout_entry PRIMARY KEY ( workout_id, exercise_id )
 );

CREATE TABLE weights (
  weight_id            serial NOT NULL,
  user_id              integer NOT NULL,
  workout_id           integer,
  weight               numeric(5, 2) NOT NULL,
  created_at           timestamp DEFAULT current_timestamp NOT NULL
);

ALTER TABLE workout_entries ADD CONSTRAINT non_negative_chk CHECK ( set_count > 0 AND reps_per_set > 0 AND weight >= 0 );

CREATE INDEX idx_workout_entry_0 ON workout_entries ( workout_id );

CREATE INDEX idx_workout_entry_1 ON workout_entries ( exercise_id );

CREATE VIEW detailed_news AS SELECT u.user_id AS friend_id, u.first_name, u.last_name,
  f.first_user_id, f.second_user_id,
  g.gym_id, g.gym_name,
  w.workout_id, w.started_at, w.finished_at, w.note,
  array_agg(DISTINCT tm.muscle_name ORDER BY tm.muscle_name) AS muscles_names,
  l.count AS likes_count, CASE WHEN l2.user_id IS NULL THEN FALSE ELSE TRUE END AS liked
FROM users u
JOIN friendships f ON u.user_id IN (f.first_user_id, f.second_user_id)
JOIN workouts w USING (user_id)
LEFT JOIN gyms g USING (gym_id)
LEFT JOIN workout_entries we USING (workout_id)
LEFT JOIN exercise_muscle_groups tm USING (exercise_id)
LEFT JOIN (SELECT count(*), workout_id FROM likes GROUP BY workout_id) l USING (workout_id)
LEFT JOIN likes l2 ON l2.workout_id = w.workout_id AND l2.user_id IN (f.first_user_id, f.second_user_id) AND l2.user_id != u.user_id
GROUP BY u.user_id, f.first_user_id, f.second_user_id, w.workout_id, g.gym_id, l.count, l2.user_id
ORDER BY w.finished_at DESC;

CREATE OR REPLACE FUNCTION random_strangers_of_user(uid int)
RETURNS TABLE(id int, first_name varchar(100), last_name varchar(100)) AS
$$
SELECT user_id, first_name, last_name
FROM USERS
WHERE user_id != uid AND user_id NOT IN
	(SELECT (CASE WHEN first_user_id = uid THEN second_user_id ELSE first_user_id END) AS friend_id
	FROM friendships
	WHERE first_user_id = uid OR second_user_id = uid)
LIMIT 5;
$$
LANGUAGE sql;

CREATE VIEW simple_news AS SELECT u.user_id AS friend_id, u.first_name, u.last_name,
    f.first_user_id, f.second_user_id,
    g.gym_id, g.gym_name,
    w.started_at, w.finished_at, w.note,
    count(l) as likes_count
  FROM users u
  JOIN friendships f ON u.user_id IN (f.first_user_id, f.second_user_id)
  JOIN workouts w ON u.user_id = w.user_id
  LEFT JOIN gyms g ON g.gym_id = w.gym_id
  LEFT JOIN likes l ON l.workout_id = w.workout_id
  GROUP BY u.user_id, f.first_user_id, f.second_user_id, g.gym_id, w.workout_id
  ORDER BY w.finished_at DESC;

CREATE OR REPLACE FUNCTION insert_friendship() RETURNS TRIGGER AS $$
    DECLARE
        first_user_id int;
        second_user_id int;
    BEGIN
        first_user_id = least(NEW.first_user_id, NEW.second_user_id);
        second_user_id = greatest(NEW.first_user_id, NEW.second_user_id);

        NEW.first_user_id = first_user_id;
        NEW.second_user_id = second_user_id;

        RETURN NEW;
    END
$$ LANGUAGE plpgsql;

CREATE TRIGGER insert_friendship_trigger
    BEFORE INSERT ON friendships
    FOR EACH ROW
    EXECUTE PROCEDURE insert_friendship();

CREATE OR REPLACE FUNCTION insert_friendship_request() RETURNS TRIGGER AS $$
    DECLARE
        _first_user_id int;
        _second_user_id int;
    BEGIN
        _first_user_id = least(NEW.first_user_id, NEW.second_user_id);
        _second_user_id = greatest(NEW.first_user_id, NEW.second_user_id);

        IF EXISTS (SELECT * FROM friendship_requests WHERE first_user_id = NEW.second_user_id AND second_user_id = NEW.first_user_id) THEN
          DELETE FROM friendship_requests WHERE first_user_id = NEW.second_user_id AND second_user_id = NEW.first_user_id;
          INSERT INTO friendships(first_user_id, second_user_id) VALUES (_first_user_id, _second_user_id);
          RETURN NULL;
        ELSE
          RETURN NEW;
        END IF;
    END
$$ LANGUAGE plpgsql;

CREATE TRIGGER insert_friendship_request_trigger
    BEFORE INSERT ON friendship_requests
    FOR EACH ROW
    EXECUTE PROCEDURE insert_friendship_request();

ALTER TABLE comments ADD CONSTRAINT fk_comments_users FOREIGN KEY ( user_id ) REFERENCES users( user_id ) ON DELETE CASCADE;

ALTER TABLE comments ADD CONSTRAINT fk_comments_workouts FOREIGN KEY ( workout_id ) REFERENCES workouts( workout_id ) ON DELETE CASCADE;

ALTER TABLE exercise_ratings ADD CONSTRAINT fk_exercises_ratings_users FOREIGN KEY ( user_id ) REFERENCES users( user_id ) ON DELETE CASCADE;

ALTER TABLE exercise_ratings ADD CONSTRAINT fk_exercises_ratings_exercises FOREIGN KEY ( exercise_id ) REFERENCES exercises( exercise_id ) ON DELETE CASCADE;

ALTER TABLE friendships ADD CONSTRAINT fk_friendships_users FOREIGN KEY ( first_user_id ) REFERENCES users( user_id );

ALTER TABLE friendships ADD CONSTRAINT fk_friendships_users2 FOREIGN KEY ( second_user_id ) REFERENCES users( user_id );

ALTER TABLE friendship_requests ADD CONSTRAINT fk_friendships_users FOREIGN KEY ( first_user_id ) REFERENCES users( user_id );

ALTER TABLE friendship_requests ADD CONSTRAINT fk_friendships_users2 FOREIGN KEY ( second_user_id ) REFERENCES users( user_id );

ALTER TABLE gym_ratings ADD CONSTRAINT fk_gym_ratings FOREIGN KEY ( gym_id ) REFERENCES gyms( gym_id ) ON DELETE CASCADE;

ALTER TABLE gym_ratings ADD CONSTRAINT fk_gym_ratings_0 FOREIGN KEY ( user_id ) REFERENCES users( user_id ) ON DELETE CASCADE;

ALTER TABLE likes ADD CONSTRAINT fk_likes_users FOREIGN KEY ( user_id ) REFERENCES users( user_id ) ON DELETE CASCADE;

ALTER TABLE likes ADD CONSTRAINT fk_likes_workouts FOREIGN KEY ( workout_id ) REFERENCES workouts( workout_id ) ON DELETE CASCADE;

ALTER TABLE exercise_muscle_groups ADD CONSTRAINT fk_exercise_muscle_groups FOREIGN KEY ( muscle_name ) REFERENCES muscle_groups( muscle_name ) ON DELETE CASCADE;

ALTER TABLE exercise_muscle_groups ADD CONSTRAINT fk_exercise_muscle_groups_exercises FOREIGN KEY ( exercise_id ) REFERENCES exercises( exercise_id ) ON DELETE CASCADE;

ALTER TABLE exercise_equipment ADD CONSTRAINT fk_exercise_equipment FOREIGN KEY ( equipment_name ) REFERENCES equipment( equipment_name ) ON DELETE CASCADE;

ALTER TABLE exercise_equipment ADD CONSTRAINT fk_exercise_equipment_exercises FOREIGN KEY ( exercise_id ) REFERENCES exercises( exercise_id ) ON DELETE CASCADE;

ALTER TABLE workout_entries ADD CONSTRAINT fk_workout_entry_workouts FOREIGN KEY ( workout_id ) REFERENCES workouts( workout_id );

ALTER TABLE workout_entries ADD CONSTRAINT fk_workout_entry_exercises FOREIGN KEY ( exercise_id ) REFERENCES exercises( exercise_id );

ALTER TABLE workouts ADD CONSTRAINT fk_workouts_users FOREIGN KEY ( user_id ) REFERENCES users( user_id );

ALTER TABLE workouts ADD CONSTRAINT fk_workouts_gyms FOREIGN KEY ( gym_id ) REFERENCES gyms( gym_id );

-- DEMO POPULATION

INSERT INTO users(login, email, password_digest, first_name, last_name, height, weight, date_of_birth) VALUES
  ('kuba', 'kuba@email.com', '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8', 'Kuba', 'Kowalski', 175, 83, '1992-02-29'::date),
  ('edzio', 'edzio@email.com', '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8', 'Edward', 'Szczypta', 180, 90, '1967-05-15'::date),
  ('hardkorowy_koksu', 'hardkorowy_koksu@email.com', '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8', 'Robert', 'Burneika', 186, 130, '1984-10-03'::date),
  ('gruby', 'gruby@email.com', '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8', 'Mateusz', 'Boczek', 170, 128, '1976-04-21'::date),
  ('lamer', 'lama@email.com', '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8', 'Kamil', 'Pietruszka', 184, 85, '1994-06-26'::date)
;

INSERT INTO friendships(first_user_id, second_user_id) VALUES
  (1, 3), (1, 4), (1, 5), (3, 4), (3, 5), (4, 5)
;

INSERT INTO muscle_groups(muscle_name) VALUES
  ('klata'), ('plecy'), ('barki'), ('biceps'), ('triceps'), ('nogi'), ('łydki')
;

INSERT INTO exercises(exercise_name) VALUES
  ('Wyciskanie sztangi - płaska ławka'),
  ('Wyciskanie sztangi - incline'),
  ('Wyciskanie sztangi - decline'),
  ('Martwy ciąg'),
  ('Arnoldki'),
  ('Wyciskanie żołnierskie'),
  ('Przysiady'),
  ('Uginanie sztangi'),
  ('Uginanie hantli z supinacją'),
  ('Francuskie wyciskanie'),
  ('Podciąganie'),
  ('Wspinanie na palce')
;

INSERT INTO exercise_muscle_groups(exercise_id, muscle_name) VALUES
  (1, 'klata'), (1, 'triceps'),
  (2, 'klata'), (2, 'triceps'),
  (3, 'klata'), (3, 'triceps'),
  (4, 'nogi'), (4, 'plecy'),
  (5, 'barki'),
  (6, 'barki'),
  (7, 'nogi'),
  (8, 'biceps'),
  (9, 'biceps'),
  (10, 'triceps'),
  (11, 'biceps'), (11, 'plecy'),
  (12, 'łydki')
;

INSERT INTO gyms(gym_name, city, street) VALUES
  ('Platinium', 'Kraków', 'Pawia 3'),
  ('PowerGym', 'Liszki', 'Piekary 6'),
  ('Body Paradise', 'Kraków', 'Pachońskiego 10')
;

INSERT INTO workouts(user_id, gym_id, started_at, finished_at, note) VALUES
  (2, 1, '2014-12-10 10:00:00'::timestamp, '2014-12-10 10:30:00'::timestamp, 'Trening zrobiony najlepiej jak się da... Ale nie lepiej ;)'),
  (3, 2, '2014-12-11 06:00:00'::timestamp, '2014-12-11 22:45:00'::timestamp, 'Njie ma lipy!'),
  (5, 3, '2014-12-14 21:00:00'::timestamp, '2014-12-14 22:30:00'::timestamp, NULL)
;

INSERT INTO workout_entries(workout_id, exercise_id, set_count, reps_per_set, weight) VALUES
  (1, 12, 1, 120, 3),
  (2, 1, 4, 10, 150),
  (2, 2, 4, 10, 130),
  (2, 3, 4, 10, 180),
  (2, 8, 5, 8, 80),
  (2, 9, 3, 8, 40),
  (2, 11, 1, 4, NULL),
  (3, 7, 4, 12, 120),
  (3, 5, 3, 10, 25),
  (3, 6, 1, 1, 60)
;

INSERT INTO exercise_ratings(user_id, exercise_id, rating) VALUES
  (1, 8, 9),
  (2, 1, 1),
  (2, 12, 3),
  (3, 1, 10),
  (3, 2, 10),
  (3, 3, 10),
  (4, 8, 8)
;

INSERT INTO likes(user_id, workout_id) VALUES
  (5, 1),
  (1, 2),
  (2, 2),
  (3, 2),
  (4, 2),
  (5, 2),
  (1, 3)
;

INSERT INTO gym_ratings(user_id, gym_id, rating) VALUES
  (1, 3, 10),
  (2, 1, 4),
  (3, 2, 10),
  (5, 1, 9),
  (5, 2, 8),
  (5, 3, 9)
;
