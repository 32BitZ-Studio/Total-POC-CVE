package database;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import models.News;
import play.db.DB;

public class NewsDao {

	private static final NewsDao INSTANCE = new NewsDao();
	
	public static NewsDao get() {
		return INSTANCE;
	}
	
	private NewsDao() {}
	
	public List<News> getNews(int userId) {
		List<News> news = new ArrayList<News>();
		
		Connection connection = null;
		try {
			connection = DB.getConnection();
			PreparedStatement statement = connection.prepareStatement(
					"SELECT * "
					+ "FROM detailed_news "
					+ "WHERE (first_user_id = ? OR second_user_id = ?) AND friend_id != ? "
					+ "LIMIT 100");
			
			statement.setInt(1, userId);
			statement.setInt(2, userId);
			statement.setInt(3, userId);
			
			ResultSet resultSet = statement.executeQuery();
			
			while (resultSet.next()) {
				News n = new News();
				n.setFriendId(resultSet.getInt("friend_id"));
				n.setFirstName(resultSet.getString("first_name"));
				n.setLastName(resultSet.getString("last_name"));
				n.setWorkoutId(resultSet.getInt("workout_id"));
				n.setGymId(resultSet.getInt("gym_id"));
				n.setGymName(resultSet.getString("gym_name"));
				n.setStartedAt(resultSet.getTimestamp("started_at"));
				n.setFinishedAt(resultSet.getTimestamp("finished_at"));
				n.setNote(resultSet.getString("note"));
				n.setLikesCount(resultSet.getInt("likes_count"));
				n.setLiked(resultSet.getBoolean("liked"));
				n.setMusclesNames((String[]) resultSet.getArray("muscles_names").getArray());
				news.add(n);
			}
			
			resultSet.close();
			statement.close();
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			if (connection != null) {
				try {
					connection.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}

		return news;
	}
}
