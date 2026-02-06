import tempfile
import subprocess


def run_go_test(root_dir, test_args):
    output = tempfile.NamedTemporaryFile(
        dir=root_dir, delete=False, prefix="go_test_output_"
    )
    output_name = output.name
    output_fileno = output.fileno()

    try:
        proc = subprocess.Popen(
            test_args,
            text=True,
            stdout=output_fileno,
            stderr=output_fileno,
        )
        return_code = proc.wait(timeout=180)
    except Exception as ex:
        raise ex
    finally:
        output.close()

    assert return_code == 0, "test failed, output: {}".format(output_name)
