# Java 17 기반 이미지 사용
FROM openjdk:17-jdk-alpine

# 'ARG' 예약어를 통해 인자로 전달
ARG SPRING_DATASOURCE_URL \
    SPRING_DATASOURCE_USERNAME \
    SPRING_DATASOURCE_PASSWORD \
    JWT_SECRET \
    NAVER_CLIENT_ID \
    NAVER_CLIENT_SECRET \
    NAVER_REDIRECT_URI \
    GOOGLE_CLIENT_ID \
    GOOGLE_CLIENT_SECRET \
    GOOGLE_REDIRECT_URI 

# 'ENV' 예약어를 통해 전달받은 값을 실제 값과 매칭
ENV SPRING_DATASOURCE_URL=${SPRING_DATASOURCE_URL} \
    SPRING_DATASOURCE_USERNAME=${SPRING_DATASOURCE_USERNAME} \
    SPRING_DATASOURCE_PASSWORD=${SPRING_DATASOURCE_PASSWORD} \
    JWT_SECRET=${JWT_SECRET} \
    NAVER_CLIENT_ID=${NAVER_CLIENT_ID} \
    NAVER_CLIENT_SECRET=${NAVER_CLIENT_SECRET} \
    NAVER_REDIRECT_URI=${NAVER_REDIRECT_URI} \
    GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID} \
    GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET} \
    GOOGLE_REDIRECT_URI=${GOOGLE_REDIRECT_URI}
    
# 작업 디렉토리 설정
WORKDIR /app

# Gradle 프로젝트 빌드 결과물 복사
COPY build/libs/*.jar app.jar

# 애플리케이션 실행
ENTRYPOINT ["java", "-jar", "app.jar"]