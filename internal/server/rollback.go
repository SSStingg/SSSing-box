package server

import (
	"fmt"
	"os"
	"path/filepath"
)

// ---------- 更新回滚（轻量设计） ----------
// 面板要轻量，本地不主动攒备份：备份只用一个固定名文件 sssingbox.bak
// （与二进制同目录），每次更新覆盖它，绝不用带时间戳的 .bak-<时间戳>
// （以前每更一次磁盘上就多一个 20MB 文件，越攒越大）。
// 新二进制启动成功、开始服务后立即删掉 .bak，平时稳态磁盘上零个备份。
// 新二进制启动失败（bind 端口、读库等初始化错误）时，main 在退出前
// 把 .bak 拷回二进制路径，systemd 重启后跑回旧版（只有 .bak 存在时
// 才这么做；稳态下没有 .bak，启动失败就是真的失败，不降级）。

// panelBackupPath：固定名备份文件路径。
func panelBackupPath(exe string) string { return exe + ".bak" }

// ErrNoBackup：没有备份文件可回滚（不是更新后的启动，或备份已被删掉）。
var ErrNoBackup = fmt.Errorf("没有备份文件可回滚")

// RestorePanelBackup：启动失败时的回滚。exe+".bak" 存在就把它换回 exe
// （旧版二进制），返回 nil；不存在返回 ErrNoBackup（调用方按“没有可
// 回滚版本”处理）；换回失败返回错误，调用方记日志后退出。
// 必须用 Rename，不能用“读出来再写回去”：正在运行的二进制文件写时会
// 报 ETXTBSY（text file busy）；Rename 只换目录项，运行中的进程继续
// 用旧 inode，不受影响。Rename 后 .bak 不再存在（它就是现在的 exe）。
func RestorePanelBackup(exe string) error {
	bak := panelBackupPath(exe)
	fi, err := os.Stat(bak)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNoBackup
		}
		return err
	}
	if fi.Size() == 0 {
		return fmt.Errorf("备份文件 %s 为空，无法回滚", bak)
	}
	if err := os.Rename(bak, exe); err != nil {
		return fmt.Errorf("回滚重命名失败：%w", err)
	}
	return nil
}

// DeletePanelBackup：启动成功后删掉备份，稳态零备份。
func DeletePanelBackup(exe string) {
	_ = os.Remove(panelBackupPath(exe))
}

// CleanupStaleBackups：更新成功时删掉以前攒下的带时间戳旧备份
// sssingbox.bak-*（固定名 .bak 本身不在此列，它是当次更新的回滚凭据）。
func CleanupStaleBackups(exe string) {
	matches, _ := filepath.Glob(exe + ".bak-*")
	for _, m := range matches {
		_ = os.Remove(m)
	}
}
