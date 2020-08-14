try:
    {}["a"]
except KeyError as ex:
    print(ex.args)
    pass
