INSERT INTO users(login, email, password_digest, first_name, last_name, height, weight, date_of_birth) VALUES
  ('kuba', 'kuba@email.com', '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8', 'Kuba', 'Kowalski', 175, 83, '1992-02-29'::date),
  ('edzio', 'edzio@email.com', '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8', 'Edward', 'Szypta', 180, 90, '1967-05-15'::date),
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

INSERT INTO target_muscles(exercise_id, muscle_name) VALUES
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

INSERT INTO comments(user_id, workout_id, content, created_at) VALUES
  (2, 2, 'Jest pompa!', '2015-01-04 12:34:56'::timestamp),
  (3, 2, 'Njie ma opjierdalanjia sie!', '2015-01-04 12:36:15'::timestamp)
;

INSERT INTO gym_ratings(user_id, gym_id, rating) VALUES
  (1, 3, 10),
  (2, 1, 4),
  (3, 2, 10),
  (5, 1, 9),
  (5, 2, 8),
  (5, 3, 9)
;