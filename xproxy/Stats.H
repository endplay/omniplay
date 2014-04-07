#ifndef Stats_H
# define Stats_H

# define STATS_OPCODE_MAX 257

class Stats
{
  public:
    Stats();
    ~Stats();

    void add(unsigned int opcode, unsigned int bitsIn, unsigned int bitsOut);
    void summarize(unsigned int &bitsIn, unsigned int &bitsOut,
                   int showDetails = 0);

  private:
    unsigned int count_[STATS_OPCODE_MAX];
    unsigned int bitsIn_[STATS_OPCODE_MAX];
    unsigned int bitsOut_[STATS_OPCODE_MAX];
};

#endif /* Stats_H */
