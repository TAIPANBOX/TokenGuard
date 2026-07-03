import XCTest

@testable import TokenFuse

/// A URLProtocol that answers requests from a canned handler — lets us test the
/// client's decoding + auth without a network.
final class MockURLProtocol: URLProtocol {
    nonisolated(unsafe) static var handler: ((URLRequest) -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = MockURLProtocol.handler else {
            client?.urlProtocolDidFinishLoading(self)
            return
        }
        let (response, data) = handler(request)
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

final class APIClientTests: XCTestCase {
    private func makeClient() -> APIClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        return APIClient(
            baseURL: URL(string: "https://plane.test")!,
            token: "devkey",
            session: URLSession(configuration: config)
        )
    }

    func testRunsDecodeAndAuthHeader() async throws {
        MockURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer devkey")
            XCTAssertEqual(request.url?.path, "/v1/runs")
            let json = """
            [{"run_id":"7f3a2b","model":"opus-4-8","spent_microusd":26100000,"calls":312,
              "cache_hits":4,"steps":41,"last_seen_millis":100,"killed":false}]
            """
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data(json.utf8))
        }

        let runs = try await makeClient().runs()
        XCTAssertEqual(runs.count, 1)
        XCTAssertEqual(runs[0].runId, "7f3a2b")
        XCTAssertEqual(runs[0].spentMicrousd, 26_100_000)
        XCTAssertEqual(runs[0].steps, 41)
        XCTAssertFalse(runs[0].killed)
        // Microdollar → dollar conversion.
        XCTAssertEqual(runs[0].spentMicrousd.usd, 26.10, accuracy: 0.0001)
    }

    func testBudgetsDecode() async throws {
        MockURLProtocol.handler = { request in
            let json = #"{"7f3a2b":25000000,"b12e90":10000000}"#
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data(json.utf8))
        }
        let budgets = try await makeClient().budgets()
        XCTAssertEqual(budgets["7f3a2b"], 25_000_000)
        XCTAssertEqual(budgets.count, 2)
    }

    func testHTTPErrorSurfaces() async {
        MockURLProtocol.handler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 401, httpVersion: nil, headerFields: nil)!
            return (response, Data("{\"error\":\"invalid api key\"}".utf8))
        }
        do {
            _ = try await makeClient().summary()
            XCTFail("expected an error for HTTP 401")
        } catch let APIClient.ClientError.http(code) {
            XCTAssertEqual(code, 401)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }
}
