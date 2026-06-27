package com.noel.springsecurity.services;

import io.github.bucket4j.Bucket;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimitingServiceTest {

    private final RateLimitingService rateLimitingService = new RateLimitingService();

    @Test
    void resolveBucket_returnsTheSameBucketForTheSameKey() {
        Bucket first = rateLimitingService.resolveBucket("192.168.1.1");
        Bucket second = rateLimitingService.resolveBucket("192.168.1.1");

        assertThat(first).isSameAs(second); // cached, not regenerated on every request
    }

    @Test
    void resolveBucket_returnsADifferentBucketForADifferentKey() {
        Bucket bucketA = rateLimitingService.resolveBucket("ip-a");
        Bucket bucketB = rateLimitingService.resolveBucket("ip-b");

        assertThat(bucketA).isNotSameAs(bucketB);
    }

    @Test
    void newBucket_allowsExactlyTenRequestsThenBlocksTheEleventh() {
        Bucket bucket = rateLimitingService.resolveBucket("burst-test-ip");

        for (int i = 0; i < 10; i++) {
            assertThat(bucket.tryConsume(1)).isTrue();
        }
        assertThat(bucket.tryConsume(1)).isFalse(); // the 11th request in the same window is rejected
    }
}