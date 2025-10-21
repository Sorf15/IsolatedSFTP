package com.sorf.IsolatedSFTP.subsystems;

import com.sorf.IsolatedSFTP.Main;
import com.sorf.IsolatedSFTP.SftpUser;
import com.sorf.IsolatedSFTP.SimpleServer;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.extensions.openssh.*;
import org.apache.sshd.sftp.server.SftpSubsystem;
import org.apache.sshd.sftp.server.SftpSubsystemConfigurator;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

public class DeniedSftpSubsystem extends SftpSubsystem {

    private boolean isAdmin;

    public DeniedSftpSubsystem(ChannelSession channel, SftpSubsystemConfigurator configurator) {
        super(channel, configurator);

        SimpleServer server = Main.server.get();
        String username = getServerSession().getUsername();
        Optional<SftpUser> user = server.getUsers().stream().filter(sftpUser -> sftpUser.getUsername().equals(username)).findAny();
        isAdmin = user.map(SftpUser::isAdmin).orElse(false);

    }

    protected void doRestrictedOpen(Buffer buffer, int length, int type, int id) throws IOException {
        String path = buffer.getString();
        int access = 0;
        int version = getVersion();
        if (version >= SftpConstants.SFTP_V5) {
            access = buffer.getInt();
            if (access == 0) {
                access = SftpConstants.ACE4_READ_DATA | SftpConstants.ACE4_READ_ATTRIBUTES;
            }
        }

        int rawPflags = buffer.getInt();
        int pflags = rawPflags;

        // --- CHECK IF READ ONLY ---
        if (version >= SftpConstants.SFTP_V5) {
            int writeLikeBits =
                    SftpConstants.ACE4_WRITE_DATA
                            | SftpConstants.ACE4_WRITE_ATTRIBUTES
                            | SftpConstants.ACE4_APPEND_DATA;
            if ((access & writeLikeBits) != 0) {
                cancel(buffer, type, id);
                return;
            }
        } else {
            int flags = (rawPflags == 0) ? SftpConstants.SSH_FXF_READ : rawPflags;

            int writeFlags = SftpConstants.SSH_FXF_WRITE
                    | SftpConstants.SSH_FXF_APPEND
                    | SftpConstants.SSH_FXF_CREAT
                    | SftpConstants.SSH_FXF_TRUNC
                    | SftpConstants.SSH_FXF_EXCL;

            if ((flags & writeFlags) != 0) {
                cancel(buffer, type, id);
                return;
            }
        }

        if (version < SftpConstants.SFTP_V5) {
            int flags = pflags == 0 ? SftpConstants.SSH_FXF_READ : pflags;
            pflags = 0;
            switch (flags & (SftpConstants.SSH_FXF_READ | SftpConstants.SSH_FXF_WRITE)) {
                case SftpConstants.SSH_FXF_READ:
                    access |= SftpConstants.ACE4_READ_DATA | SftpConstants.ACE4_READ_ATTRIBUTES;
                    break;
                case SftpConstants.SSH_FXF_WRITE:
                    access |= SftpConstants.ACE4_WRITE_DATA | SftpConstants.ACE4_WRITE_ATTRIBUTES;
                    break;
                default:
                    access |= SftpConstants.ACE4_READ_DATA | SftpConstants.ACE4_READ_ATTRIBUTES;
                    access |= SftpConstants.ACE4_WRITE_DATA | SftpConstants.ACE4_WRITE_ATTRIBUTES;
                    break;
            }
            if ((flags & SftpConstants.SSH_FXF_APPEND) != 0) {
                access |= SftpConstants.ACE4_APPEND_DATA;
                pflags |= SftpConstants.SSH_FXF_APPEND_DATA | SftpConstants.SSH_FXF_APPEND_DATA_ATOMIC;
            }
            if ((flags & SftpConstants.SSH_FXF_CREAT) != 0) {
                if ((flags & SftpConstants.SSH_FXF_EXCL) != 0) {
                    pflags |= SftpConstants.SSH_FXF_CREATE_NEW;
                } else if ((flags & SftpConstants.SSH_FXF_TRUNC) != 0) {
                    pflags |= SftpConstants.SSH_FXF_CREATE_TRUNCATE;
                } else {
                    pflags |= SftpConstants.SSH_FXF_OPEN_OR_CREATE;
                }
            } else {
                if ((flags & SftpConstants.SSH_FXF_TRUNC) != 0) {
                    pflags |= SftpConstants.SSH_FXF_TRUNCATE_EXISTING;
                } else {
                    pflags |= SftpConstants.SSH_FXF_OPEN_EXISTING;
                }
            }
        }

        Map<String, Object> attrs = readAttrs(buffer);
        String handle;
        try {
            handle = doOpen(id, path, pflags, access, attrs);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e, SftpConstants.SSH_FXP_OPEN, path);
            return;
        }

        sendHandle(prepareReply(buffer), id, handle);
    }

    @Override
    protected void executeExtendedCommand(Buffer buffer, int id, String extension) throws IOException {
        switch (extension) {
            case SftpConstants.EXT_TEXT_SEEK:
                doTextSeek(buffer, id);
                break;
            case SftpConstants.EXT_VERSION_SELECT:
                doVersionSelect(buffer, id);
                break;
            case SftpConstants.EXT_COPY_FILE:
                if (isAdmin(buffer, id, extension)) doCopyFile(buffer, id);
                break;
            case SftpConstants.EXT_COPY_DATA:
                if (isAdmin(buffer, id, extension)) doCopyData(buffer, id);
                break;
            case SftpConstants.EXT_MD5_HASH:
            case SftpConstants.EXT_MD5_HASH_HANDLE:
                doMD5Hash(buffer, id, extension);
                break;
            case SftpConstants.EXT_CHECK_FILE_HANDLE:
            case SftpConstants.EXT_CHECK_FILE_NAME:
                doCheckFileHash(buffer, id, extension);
                break;
            case FsyncExtensionParser.NAME:
                if (isAdmin(buffer, id, extension)) doOpenSSHFsync(buffer, id);
                break;
            case SftpConstants.EXT_SPACE_AVAILABLE:
                doSpaceAvailable(buffer, id);
                break;
            case HardLinkExtensionParser.NAME:
                if (isAdmin(buffer, id, extension)) doOpenSSHHardLink(buffer, id);
                break;
            case LSetStatExtensionParser.NAME:
                if (isAdmin(buffer, id, extension)) doSetStat(buffer, id, extension, -1, Boolean.FALSE);
                break;
            case PosixRenameExtensionParser.NAME:
                if (isAdmin(buffer, id, extension)) doPosixRename(buffer, id);
                break;
            case LimitsExtensionParser.NAME:
                doOpenSSHLimits(buffer, id);
                break;
            default:
                doUnsupportedExtension(buffer, id, extension);
        }
    }

    @Override
    protected void doProcess(Buffer buffer, int length, int type, int id) throws IOException {
        switch (type) {
            case SftpConstants.SSH_FXP_INIT:
                doInit(buffer, id);
                break;
            case SftpConstants.SSH_FXP_OPEN:
                if (isAdmin) doOpen(buffer, id);
                else doRestrictedOpen(buffer, length, type, id);
                break;
            case SftpConstants.SSH_FXP_CLOSE:
                doClose(buffer, id);
                break;
            case SftpConstants.SSH_FXP_READ:
                doRead(buffer, id);
                break;
            case SftpConstants.SSH_FXP_WRITE:
                if (isAdmin(buffer, length, type, id)) doWrite(buffer, id);
                break;
            case SftpConstants.SSH_FXP_LSTAT:
                doLStat(buffer, id);
                break;
            case SftpConstants.SSH_FXP_FSTAT:
                doFStat(buffer, id);
                break;
            case SftpConstants.SSH_FXP_SETSTAT:
                if (isAdmin(buffer, length, type, id)) doSetStat(buffer, id, "", type, null);
                break;
            case SftpConstants.SSH_FXP_FSETSTAT:
                if (isAdmin(buffer, length, type, id)) doFSetStat(buffer, id);
                break;
            case SftpConstants.SSH_FXP_OPENDIR:
                doOpenDir(buffer, id);
                break;
            case SftpConstants.SSH_FXP_READDIR:
                doReadDir(buffer, id);
                break;
            case SftpConstants.SSH_FXP_REMOVE:
                if (isAdmin(buffer, length, type, id)) doRemove(buffer, id);
                break;
            case SftpConstants.SSH_FXP_MKDIR:
                if (isAdmin(buffer, length, type, id)) doMakeDirectory(buffer, id);
                break;
            case SftpConstants.SSH_FXP_RMDIR:
                if (isAdmin(buffer, length, type, id)) doRemoveDirectory(buffer, id);
                break;
            case SftpConstants.SSH_FXP_REALPATH:
                doRealPath(buffer, id);
                break;
            case SftpConstants.SSH_FXP_STAT:
                doStat(buffer, id);
                break;
            case SftpConstants.SSH_FXP_RENAME:
                if (isAdmin(buffer, length, type, id)) doRename(buffer, id);
                break;
            case SftpConstants.SSH_FXP_READLINK:
                doReadLink(buffer, id);
                break;
            case SftpConstants.SSH_FXP_SYMLINK:
                if (isAdmin(buffer, length, type, id)) doSymLink(buffer, id);
                break;
            case SftpConstants.SSH_FXP_LINK:
                if (isAdmin(buffer, length, type, id)) doLink(buffer, id);
                break;
            case SftpConstants.SSH_FXP_BLOCK:
                if (isAdmin(buffer, length, type, id)) doBlock(buffer, id);
                break;
            case SftpConstants.SSH_FXP_UNBLOCK:
                if (isAdmin(buffer, length, type, id)) doUnblock(buffer, id);
                break;
            case SftpConstants.SSH_FXP_EXTENDED:
                doExtended(buffer, id);
                break;
            default:
                doUnsupported(buffer, length, type, id);
                break;
        }
        if (type != SftpConstants.SSH_FXP_INIT) {
            requestsCount.incrementAndGet();
        }
    }

    private boolean isAdmin(Buffer buffer, int id, String reason) throws IOException {
        if (!isAdmin) {
            cancel(buffer, id, reason);
        }
        return isAdmin;
    }

    private boolean isAdmin(Buffer buffer, int length, int type, int id) throws IOException {
        return isAdmin(buffer, id, SftpConstants.getCommandMessageName(type));
    }

    private void cancel(Buffer buffer, int type, int id) throws IOException {
        cancel(buffer,id,SftpConstants.getCommandMessageName(type));
    }

    private void cancel(Buffer buffer, int id, String reason) throws IOException {
        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_PERMISSION_DENIED,
                "Command " + reason + " is not allowed for this user");
    }

    public static class Factory extends SftpSubsystemFactory {
        @Override
        public Command createSubsystem(ChannelSession channel) throws IOException {
            DeniedSftpSubsystem subsystem = new DeniedSftpSubsystem(channel, this);
            GenericUtils.forEach(getRegisteredListeners(), subsystem::addSftpEventListener);
            return subsystem;
        }
    }
}
