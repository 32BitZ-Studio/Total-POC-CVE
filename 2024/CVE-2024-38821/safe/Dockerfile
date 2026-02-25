# Build stage: Build the project using Gradle
FROM gradle:8.12.0-jdk21 AS build

WORKDIR /home/gradle/project

# Copy the source code
COPY --chown=gradle:gradle . .

# Execute the build with Gradle
RUN gradle bootJar --no-daemon

# Execution stage: Run the application using a lightweight OpenJDK image
FROM openjdk:21-jdk-slim

WORKDIR /app

# Copy the build artifact (JAR file)
COPY --from=build /home/gradle/project/build/libs/*.jar app.jar

# Run the application
CMD ["java", "-jar", "app.jar"]

EXPOSE 8080
