import SwiftUI

struct SystemTimeZoneEditor: View {
    @Environment(\.dismiss) private var dismiss
    @AppStorage(SystemTimeZoneCommand.preference) private var saved: String?
    @State private var selected: String?
    @State private var picking = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Часовой пояс при включённых правилах").font(.headline)
            Text("SplitLane применит пояс ко всему Mac при включении правил и вернёт прежний при выключении.")
                .foregroundStyle(.secondary)
            Button {
                picking.toggle()
            } label: {
                Label(selected ?? "Оставить текущий", systemImage: "chevron.up.chevron.down")
            }
            .popover(isPresented: $picking, arrowEdge: .bottom) {
                TimeZonePicker(selection: $selected, defaultTitle: "Оставить текущий", includesUTC: false) { picking = false }
            }
            HStack {
                Spacer()
                Button("Отмена", role: .cancel) { dismiss() }
                Button("Сохранить") {
                    saved = selected
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 380)
        .onAppear { selected = saved }
    }
}
