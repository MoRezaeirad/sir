package classify

import "testing"

func TestIsDangerousShellCommand(t *testing.T) {
	dangerous := []struct {
		name string
		cmd  string
	}{
		{"rm root", "rm -rf /"},
		{"rm home", "rm --recursive --force $HOME"},
		{"rm home glob", "rm -rf $HOME/*"},
		{"rm current tree", "rm -fr ./*"},
		{"find delete root", "find / -name tmp -delete"},
		{"find exec rm", "find . -name '*.tmp' -exec rm -rf {} +"},
		{"mkfs variant", "mkfs.ext4 /dev/sdb1"},
		{"dd block device", "dd if=/dev/zero of=/dev/sda bs=1M"},
		{"tee block device", "tee /dev/sda"},
		{"copy to block device", "cp image.raw /dev/nvme0n1"},
		{"shred device", "shred /dev/nvme0n1"},
		{"world writable recursive", "chmod -R 777 ."},
		{"chown root", "chown -R app:app /"},
		{"git clean ignored", "git clean -ffdx"},
		{"git reset hard", "git reset --hard"},
		{"git checkout current", "git checkout -- ."},
		{"mac erase disk", "diskutil eraseDisk APFS Test /dev/disk2"},
		{"mac apfs delete container", "diskutil apfs deleteContainer disk3"},
		{"mac asr erase", "asr restore --source img.dmg --target /dev/disk2 --erase"},
		{"powershell remove root", `powershell -Command "Remove-Item -Recurse -Force C:\"`},
		{"pwsh remove home", `pwsh -c "Remove-Item -Recurse -Force $HOME"`},
		{"cmd rmdir root", `cmd.exe /c rd /s /q C:\`},
		{"cmd delete drive", `del /s /q C:\*`},
		{"windows format", "format C:"},
		{"diskpart", "diskpart /s wipe.txt"},
		{"icacls full control", `icacls C:\ /grant Everyone:F /T`},
		{"takeown root", `takeown /F C:\ /R`},
		{"cipher wipe", `cipher /w:C:\`},
		{"fork bomb", ":(){ :|:& };:"},
		{"kill all", "kill -9 -1"},
		{"redirect to disk", "yes > /dev/sda"},
		{"git clean separated flags", "git clean -f -d -x"},
		{"git clean separated reordered", "git clean -x -f -d"},
		{"git clean long force separated", "git clean --force -d -x"},
		{"chmod recursive other-writable", "chmod -R o+w ."},
		{"chmod recursive plus-write", "chmod -R +w ."},
		{"chmod recursive 666", "chmod -R 666 ."},
	}

	for _, tc := range dangerous {
		t.Run(tc.name, func(t *testing.T) {
			if !IsDangerousShellCommand(tc.cmd) {
				t.Fatalf("IsDangerousShellCommand(%q) = false, want true", tc.cmd)
			}
		})
	}
}

func TestIsDangerousShellCommandBenignCleanup(t *testing.T) {
	benign := []struct {
		name string
		cmd  string
	}{
		{"rm node_modules", "rm -rf node_modules"},
		{"rm build dirs", "rm -rf build target dist"},
		{"rm home cache", "rm -rf $HOME/.cache/my-tool"},
		{"find build delete", "find build -name '*.tmp' -delete"},
		{"dd stdout", "dd if=.env of=/dev/stdout"},
		{"dd image file", "dd if=/dev/zero of=/tmp/image.img bs=1M count=10"},
		{"copy from block device", "cp /dev/sda backup.img"},
		{"tee stdout", "tee /dev/stdout"},
		{"chmod single file", "chmod 777 script.sh"},
		{"chown build dir", "chown -R app:app build"},
		{"git clean no x", "git clean -fd"},
		{"git checkout branch", "git checkout main"},
		{"diskutil list", "diskutil list"},
		{"powershell list", `powershell -Command "Get-ChildItem C:\"`},
		{"cmd dir", `cmd /c dir C:\`},
		{"cmd del file", `del /q build\file.txt`},
	}

	for _, tc := range benign {
		t.Run(tc.name, func(t *testing.T) {
			if IsDangerousShellCommand(tc.cmd) {
				t.Fatalf("IsDangerousShellCommand(%q) = true, want false", tc.cmd)
			}
		})
	}
}
