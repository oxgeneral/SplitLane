import Foundation
import Security

struct ProxyCredentials: Codable, Sendable {
    var username = ""
    var password = ""

    var isEmpty: Bool { username.isEmpty && password.isEmpty }

    func isValid(for kind: RouteKind) -> Bool {
        guard !username.isEmpty else { return false }
        if kind == .socks5 {
            return username.utf8.count <= 255 && (1...255).contains(password.utf8.count)
        }
        return (kind == .http || kind == .https) && !username.contains(":") &&
            !username.utf8.contains(where: { $0 < 32 || $0 == 127 }) &&
            !password.utf8.contains(where: { $0 < 32 || $0 == 127 })
    }

    static func load(_ id: UUID) throws -> ProxyCredentials {
        var query = item(id)
        query[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            throw TunConfiguration.failure(status == errSecItemNotFound
                ? "В Связке ключей нет логина и пароля для этого прокси. Введи их заново в настройках группы."
                : "Не удалось прочитать данные прокси из Связки ключей.")
        }
        return try JSONDecoder().decode(Self.self, from: data)
    }

    func save(_ id: UUID) throws {
        let query = Self.item(id)
        let attributes = [kSecValueData as String: try JSONEncoder().encode(self)]
        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            let newItem = query.merging(attributes) { _, data in data }
            status = SecItemAdd(newItem as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw TunConfiguration.failure("Не удалось сохранить данные прокси в Связке ключей.")
        }
    }

    static func remove(_ id: UUID) throws {
        let status = SecItemDelete(item(id) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw TunConfiguration.failure("Не удалось удалить данные прокси из Связки ключей.")
        }
    }

    private static func item(_ id: UUID) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "local.splitwebonmac.proxy",
            kSecAttrAccount as String: id.uuidString
        ]
    }
}
