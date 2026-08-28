# Package marker for the fixture's base commit.
#
# This exists so `src/` is a tracked, non-empty package on the destination branch
# before either case adds its file. git does not track empty directories, so
# without a file here `src/` would only spring into existence as part of the
# feature commit, and the diff the gate sees would differ from the one validated
# against a real CodeCommit repository.
