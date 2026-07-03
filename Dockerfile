FROM eclipse-temurin:21-jdk-jammy AS builder
WORKDIR /build

COPY mvnw ./
COPY .mvn/ .mvn/
COPY pom.xml ./

RUN chmod +x mvnw

RUN ./mvnw dependency:go-offline -B --no-transfer-progress

COPY src/ ./src/

RUN ./mvnw package -DskipTests -B --no-transfer-progress


FROM eclipse-temurin:21-jre-jammy AS extractor
WORKDIR /extract

COPY --from=builder /build/target/*.jar app.jar

RUN java -Djarmode=layertools -jar app.jar extract --destination extracted/


FROM eclipse-temurin:21-jre-jammy AS runner

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system appgroup \
    && useradd --system --gid appgroup --no-create-home appuser

WORKDIR /app

COPY --from=extractor /extract/extracted/dependencies/          ./
COPY --from=extractor /extract/extracted/spring-boot-loader/    ./
COPY --from=extractor /extract/extracted/snapshot-dependencies/ ./
COPY --from=extractor /extract/extracted/application/           ./

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080

ENV JAVA_TOOL_OPTIONS="\
  -XX:+UseContainerSupport \
  -XX:MaxRAMPercentage=75.0 \
  -XX:+ExitOnOutOfMemoryError \
  -Djava.security.egd=file:/dev/./urandom"

HEALTHCHECK \
  --interval=30s \
  --timeout=10s \
  --start-period=60s \
  --retries=3 \
  CMD curl -f http://localhost:8081/actuator/health || exit 1

ENTRYPOINT ["java", "org.springframework.boot.loader.launch.JarLauncher"]